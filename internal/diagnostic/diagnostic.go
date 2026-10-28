// Package diagnostic extracts allowlisted metadata without formatting errors.
package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Cause never includes error messages, PostgreSQL detail fields or connection
// configuration. A network error alone does not prove a database outage.
func Cause(err error) (category, sqlstate string) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && validSQLState(pg.Code) {
		sqlstate = pg.Code
	}
	var connect *pgconn.ConnectError
	var network *net.OpError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		category = "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		category = "context_canceled"
	case strings.HasPrefix(sqlstate, "08") || sqlstate == "57P01" || sqlstate == "57P02" || sqlstate == "57P03" || sqlstate == "53300":
		category = "database_unavailable"
	case pg != nil:
		category = "postgresql"
	case errors.As(err, &connect):
		category = "database_unavailable"
	case errors.As(err, &network):
		category = "network"
	default:
		category = "internal"
	}
	return category, sqlstate
}

func validSQLState(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, c := range code {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// Log returns the category also used by the request-completion event.
// operation must be a constant defined by the caller, never a URL or SQL string.
func Log(logger *slog.Logger, requestID, operation string, err error) string {
	category, sqlstate := Cause(err)
	attrs := []any{"operation", operation, "cause_category", category}
	if requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}
	if sqlstate != "" {
		attrs = append(attrs, "sqlstate", sqlstate)
	}
	logger.Error("operation failed", attrs...)
	return category
}

// PanicStack records symbols and source locations, without argument values or
// the panic payload. runtime/debug.Stack also prints raw argument words.
func PanicStack() string {
	var pcs [64]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	var stack strings.Builder
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&stack, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			return stack.String()
		}
	}
}
