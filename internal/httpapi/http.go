// Package httpapi adapts the threat service to its OpenAPI HTTP contract.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/time/rate"
	"threatservice/api"
	"threatservice/internal/diagnostic"
	"threatservice/internal/threat"
)

// Service is the storage-independent interface needed by HTTP handlers.
type Service interface {
	Create(context.Context, string, threat.Input) (threat.Threat, error)
	GetByMD5(context.Context, string) (threat.Threat, error)
	Replace(context.Context, string, threat.Input) (threat.Threat, error)
}

// Options configures transport limits and optional, per-instance protection.
// Empty BearerToken and a zero RateLimitRPS disable their respective features.
type Options struct {
	Logger         *slog.Logger
	RequestTimeout time.Duration
	MaxBodyBytes   int64
	BearerToken    string
	RateLimitRPS   float64
	RateLimitBurst int
	// Ready must honor its context, including while waiting for a pool connection.
	Ready func(context.Context) error
}

type handler struct {
	service   Service
	options   Options
	tokenHash [32]byte
	limiter   *rate.Limiter
	readiness readinessCache
}

// New returns an HTTP handler. It deliberately avoids ServeMux's implicit HEAD
// support and path-cleaning redirects, which differ from the supplied contract.
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

type responseState struct {
	http.ResponseWriter
	status     int
	route      string
	errorClass string
	head       bool
	logger     *slog.Logger
	requestID  string
	operation  string
}

func (w *responseState) internalError(err error, operation string) {
	if operation == "" {
		operation = w.operation
	}
	if errors.Is(err, errReadinessPanic) {
		w.errorClass = "panic"
		w.logger.Error("operation failed", "request_id", w.requestID, "operation", operation, "cause_category", "panic")
		return
	}
	w.errorClass = diagnostic.Log(w.logger, w.requestID, operation, err)
}

func (w *responseState) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseState) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseState) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.head {
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
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
		// Bound unread bodies even when routing, authorization or media-type
		// validation rejects a request before readBody. HTTP/1 may otherwise
		// drain the unread body while trying to send that error response.
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
		// A valid encoded MD5 occupies at most 32 percent-encoded bytes.
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
			// Rejected requests must not reserve future capacity. Retry-After
			// is an estimate for this process, not a promise under concurrency.
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

func (h *handler) authorized(r *http.Request) bool {
	if h.options.BearerToken == "" {
		return true
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	value := strings.TrimSpace(values[0])
	separator := strings.IndexFunc(value, unicode.IsSpace)
	if separator < 0 || !strings.EqualFold(value[:separator], "Bearer") {
		return false
	}
	token := strings.TrimSpace(value[separator:])
	if token == "" || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash[:], h.tokenHash[:]) == 1
}

func (h *handler) readBody(w *responseState, r *http.Request) ([]byte, bool) {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		writeError(w, 415, "Unsupported media type", "")
		return nil, false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" {
		writeError(w, 415, "Unsupported media type", "")
		return nil, false
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			writeError(w, 415, "Unsupported media type", "")
			return nil, false
		}
	}
	encoding := strings.TrimSpace(strings.Join(r.Header.Values("Content-Encoding"), ","))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		writeError(w, 415, "Unsupported media type", "")
		return nil, false
	}
	if r.ContentLength > h.options.MaxBodyBytes {
		writeError(w, 413, "Request body too large", "")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.options.MaxBodyBytes+1))
	if err != nil {
		if r.Context().Err() != nil {
			w.internalError(r.Context().Err(), "read_body")
			writeError(w, 500, "Internal server error", "")
		} else {
			writeError(w, 400, "Invalid request", "could not read request body")
		}
		return nil, false
	}
	if int64(len(body)) > h.options.MaxBodyBytes {
		writeError(w, 413, "Request body too large", "")
		return nil, false
	}
	return body, true
}

func handleError(w *responseState, err error) {
	var validation *threat.ValidationError
	switch {
	case errors.As(err, &validation):
		writeError(w, 400, "Invalid request", validation.Error())
	case errors.Is(err, threat.ErrNotFound):
		writeError(w, 404, "Threat not found", "No threat with the specified MD5 found")
	case errors.Is(err, threat.ErrAlreadyExists):
		writeError(w, 409, "Threat already exists", "")
	default:
		w.internalError(err, "")
		writeError(w, 500, "Internal server error", "")
	}
}

func methodError(w *responseState, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
}

func writeError(w *responseState, status int, message, details string) {
	if w.errorClass == "" {
		w.errorClass = strconv.Itoa(status)
	}
	response := api.ErrorResponse{Message: message}
	if details != "" {
		response.Details = &details
	}
	writeJSON(w, status, response)
}

func writeJSON(w *responseState, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		body = []byte(`{"message":"Internal server error"}`)
		status = 500
		w.internalError(err, "serialize_response")
	}
	w.WriteHeader(status)
	if _, err := w.Write(append(body, '\n')); err != nil {
		w.internalError(err, "write_response")
	}
}

func requestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(value[:])
}
