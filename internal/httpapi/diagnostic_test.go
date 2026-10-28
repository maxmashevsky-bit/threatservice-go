package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"threatservice/internal/threat"
)

func logEvents(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(logs.Bytes()))
	var result []map[string]any
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			return result
		}
		result = append(result, entry)
	}
}

func TestUnexpectedErrorsHaveCorrelatedSafeDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, category, sqlstate string
		err                      error
	}{
		{"internal", "internal", "", errors.New("postgres://user:SECRET@private/db")},
		{"deadline", "deadline_exceeded", "57014", errors.Join(context.DeadlineExceeded, &pgconn.PgError{Code: "57014", Message: "SECRET"})},
		{"canceled", "context_canceled", "", context.Canceled},
		{"database unavailable", "database_unavailable", "08006", &pgconn.PgError{Code: "08006", Message: "SECRET"}},
		{"postgresql", "postgresql", "42501", &pgconn.PgError{Code: "42501", Detail: "SECRET", Hint: "SECRET", InternalQuery: "SECRET", Where: "SECRET", TableName: "SECRET"}},
	} {
		for method, operation := range map[string]string{"POST": "create_threat", "GET": "get_threat", "PUT": "replace_threat"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				var logs bytes.Buffer
				options := testOptions()
				options.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
				path := "/info/" + hash
				if method == "POST" {
					path = "/info"
				}
				r := httptest.NewRequest(method, path+"?password=SECRET", strings.NewReader(`{"md5":"`+hash+`","name":"SECRET"}`))
				if method == "PUT" {
					r = httptest.NewRequest(method, path+"?password=SECRET", strings.NewReader(`{"name":"SECRET"}`))
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer SECRET")
				w := httptest.NewRecorder()
				New(threat.NewService(&testRepository{err: tc.err}), options).ServeHTTP(w, r)
				if w.Code != 500 || w.Body.String() != "{\"message\":\"Internal server error\"}\n" {
					t.Fatalf("unsafe response: %d %s", w.Code, w.Body.String())
				}
				if strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), hash) {
					t.Fatalf("unsafe log: %s", logs.String())
				}
				entries := logEvents(t, &logs)
				if len(entries) != 2 || entries[0]["level"] != "ERROR" || entries[1]["level"] != "INFO" {
					t.Fatalf("missing error/completion events: %v", entries)
				}
				for _, entry := range entries {
					if entry["request_id"] != w.Header().Get("X-Request-ID") || entry["operation"] != operation {
						t.Fatalf("unlinked diagnostic: %v", entry)
					}
				}
				if entries[0]["cause_category"] != tc.category || entries[1]["error_class"] != tc.category {
					t.Fatalf("wrong cause: %v", entries)
				}
				if code, _ := entries[0]["sqlstate"].(string); code != tc.sqlstate {
					t.Fatalf("SQLSTATE=%q", code)
				}
			})
		}
	}
}

func TestReadinessFailureLogsSafeCategoryAndRequestID(t *testing.T) {
	var logs bytes.Buffer
	options := testOptions()
	options.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	options.Ready = func(context.Context) error { return &pgconn.PgError{Code: "57P01", Detail: "SECRET"} }
	w := request(New(nil, options), "GET", "/health/ready", "")
	if w.Code != 503 || strings.Contains(w.Body.String(), "SECRET") || strings.Contains(logs.String(), "SECRET") {
		t.Fatalf("unsafe readiness failure: %d %s %s", w.Code, w.Body.String(), logs.String())
	}
	entry := logEvents(t, &logs)[0]
	if entry["request_id"] != w.Header().Get("X-Request-ID") || entry["operation"] != "readiness" || entry["cause_category"] != "database_unavailable" || entry["sqlstate"] != "57P01" {
		t.Fatalf("missing readiness cause: %v", entry)
	}
}
