package httpapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"threatservice/api"
	"threatservice/internal/diagnostic"
	"threatservice/internal/threat"
)

type Service interface {
	Create(context.Context, string, threat.Input) (threat.Threat, error)
	GetByMD5(context.Context, string) (threat.Threat, error)
	Replace(context.Context, string, threat.Input) (threat.Threat, error)
}

type Options struct {
	Logger         *slog.Logger
	RequestTimeout time.Duration
	MaxBodyBytes   int64
	BearerToken    string
	RateLimitRPS   float64
	RateLimitBurst int
	Ready          func(context.Context) error
}

type handler struct {
	service   Service
	options   Options
	tokenHash [32]byte
	limiter   *rate.Limiter
	readiness readinessCache
}

func New(service Service, options Options) http.Handler {
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = 3 * time.Second
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = 65536
	}
	h := &handler{service: service, options: options, tokenHash: sha256.Sum256([]byte(options.BearerToken))}
	if options.RateLimitRPS > 0 {
		burst := options.RateLimitBurst
		if burst <= 0 {
			burst = int(math.Ceil(options.RateLimitRPS))
			if burst < 1 {
				burst = 1
			}
		}
		h.limiter = rate.NewLimiter(rate.Limit(options.RateLimitRPS), burst)
	}
	return h
}

func (h *handler) ServeHTTP(raw http.ResponseWriter, r *http.Request) {
	started := time.Now()
	id := requestID()
	w := &responseState{ResponseWriter: raw, route: "unknown", head: r.Method == http.MethodHead,
		logger: h.options.Logger, requestID: id, operation: "route_request"}
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(r.Context(), h.options.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	defer func() {
		if recovered := recover(); recovered != nil {
			w.errorClass = "panic"
			h.options.Logger.Error("request panicked", "request_id", id, "operation", w.operation,
				"cause_category", "panic", "stack", diagnostic.PanicStack())
			if w.status == 0 {
				writeError(w, 500, "Internal server error", "")
			}
		}
		status := w.status
		if status == 0 {
			status = http.StatusOK
		}
		h.options.Logger.Info("request completed", "request_id", id, "method", r.Method, "route", w.route, "operation", w.operation, "status", status, "duration_ms", time.Since(started).Milliseconds(), "error_class", w.errorClass)
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			w.internalError(err, "set_read_deadline")
			writeError(w, 500, "Internal server error", "")
			return
		}
	}
	h.serve(w, r)
}

func (h *handler) serve(w *responseState, r *http.Request) {
	path := r.URL.EscapedPath()
	if path == "/health/live" || path == "/health/ready" {
		w.route = path
		if r.Method != http.MethodGet {
			methodError(w, "GET")
			return
		}
		w.operation = "liveness"
		if path == "/health/ready" {
			w.operation = "readiness"
			timeout := min(readinessTimeout, h.options.RequestTimeout)
			if err := h.readiness.check(r.Context(), timeout, h.options.Ready, h.options.Logger, w.requestID); err != nil {
				w.internalError(err, "")
				writeError(w, http.StatusServiceUnavailable, "Service not ready", "")
				return
			}
		}
		writeJSON(w, http.StatusOK, api.HealthResponse{Status: "ok"})
		return
	}
	var md5 string
	collection := path == "/info"
	if collection {
		w.route = "/info"
		w.operation = "create_threat"
		if r.Method != http.MethodPost {
			methodError(w, "POST")
			return
		}
	} else {
		segment, matched := strings.CutPrefix(path, "/info/")
		if !matched || segment == "" || segment == "." || segment == ".." || strings.Contains(segment, "/") {
			writeError(w, http.StatusNotFound, "Route not found", "")
			return
		}
		w.route = "/info/{md5}"
		w.operation = "get_threat"
		if r.Method == http.MethodPut {
			w.operation = "replace_threat"
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPut {
			methodError(w, "GET, PUT")
			return
		}
		if len(segment) > 96 {
			writeError(w, 400, "Invalid request", "invalid MD5 path")
			return
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			writeError(w, 400, "Invalid request", "invalid MD5 path")
			return
		}
		md5, err = threat.NormalizeMD5(decoded)
		if err != nil {
			handleError(w, err)
			return
		}
	}
	if !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	if h.limiter != nil {
		now := time.Now()
		if !h.limiter.AllowN(now, 1) {
			retry := math.Ceil((1 - h.limiter.TokensAt(now)) / float64(h.limiter.Limit()))
			if retry < 1 || retry > 86400 {
				retry = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retry), 10))
			writeError(w, http.StatusTooManyRequests, "Rate limit exceeded", "")
			return
		}
	}
	var result threat.Threat
	var err error
	if r.Method == http.MethodGet {
		result, err = h.service.GetByMD5(r.Context(), md5)
	} else {
		body, ok := h.readBody(w, r)
		if !ok {
			return
		}
		if collection {
			var request api.ThreatCreateRequest
			if err := decodeObject(body, []string{"md5", "name", "description", "severity"}, []string{"md5", "name"}, &request); err != nil {
				writeError(w, 400, "Invalid request", err.Error())
				return
			}
			result, err = h.service.Create(r.Context(), request.Md5, input(request.Name, request.Description, request.Severity))
		} else {
			var request api.ThreatUpdateRequest
			if err := decodeObject(body, []string{"name", "description", "severity"}, []string{"name"}, &request); err != nil {
				writeError(w, 400, "Invalid request", err.Error())
				return
			}
			result, err = h.service.Replace(r.Context(), md5, input(request.Name, request.Description, request.Severity))
		}
	}
	if err != nil {
		handleError(w, err)
		return
	}
	status := http.StatusOK
	if collection {
		status = http.StatusCreated
		w.Header().Set("Location", "/info/"+result.MD5)
	}
	created, updated, hash := result.CreatedAt.UTC(), result.UpdatedAt.UTC(), result.MD5
	writeJSON(w, status, api.ThreatResponse{Md5: &hash, Name: result.Name, Description: result.Description, Severity: api.Severity(result.Severity), CreatedAt: &created, UpdatedAt: &updated})
}

func input(name string, description *string, severity *api.Severity) threat.Input {
	value := threat.Input{Name: name, Severity: threat.SeverityUnknown}
	if description != nil {
		value.Description = *description
	}
	if severity != nil {
		value.Severity = threat.Severity(*severity)
	}
	return value
}
