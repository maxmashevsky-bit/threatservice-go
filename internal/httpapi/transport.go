package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"threatservice/api"
	"threatservice/internal/diagnostic"
	"threatservice/internal/threat"
)

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
