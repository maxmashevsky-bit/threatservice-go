package diagnostic

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type unprintableError struct{}

func (unprintableError) Error() string { panic("Error must never be called") }

func TestCauseAndLogsUseOnlyAllowlistedFields(t *testing.T) {
	for _, tc := range []struct {
		name, category, code string
		err                  error
	}{
		{"opaque", "internal", "", unprintableError{}},
		{"cancel", "context_canceled", "57014", errors.Join(context.Canceled, &pgconn.PgError{Code: "57014", Message: "SECRET"})},
		{"deadline", "deadline_exceeded", "", context.DeadlineExceeded},
		{"connection", "database_unavailable", "08006", &pgconn.PgError{Code: "08006", Detail: "SECRET"}},
		{"shutdown", "database_unavailable", "57P03", &pgconn.PgError{Code: "57P03"}},
		{"capacity", "database_unavailable", "53300", &pgconn.PgError{Code: "53300"}},
		{"postgres", "postgresql", "42501", &pgconn.PgError{Code: "42501", Message: "SECRET", Detail: "SECRET", Hint: "SECRET", Where: "SECRET", InternalQuery: "SECRET", SchemaName: "SECRET", TableName: "SECRET", ColumnName: "SECRET", ConstraintName: "SECRET"}},
		{"invalid code", "postgresql", "", &pgconn.PgError{Code: "SECRET"}},
		{"connect", "database_unavailable", "", &pgconn.ConnectError{}},
		{"network", "network", "", &net.OpError{Op: "SECRET", Net: "SECRET", Err: errors.New("SECRET")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			category, state := Cause(tc.err)
			if category != tc.category || state != tc.code {
				t.Fatalf("category=%s sqlstate=%s", category, state)
			}
			var output bytes.Buffer
			Log(slog.New(slog.NewJSONHandler(&output, nil)), "request-123", "get_threat", tc.err)
			if strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), `"level":"ERROR"`) {
				t.Fatalf("unsafe or missing diagnostic: %s", output.String())
			}
		})
	}
}
