package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"threatservice/internal/config"
)

func TestStartupAndTransportDiagnosticsDoNotExposeSecrets(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	err := run(context.Background(), config.Config{DatabaseURL: "postgres://user:SECRET%zz@private/db"}, logger)
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), `"operation":"parse_database_config"`) {
		t.Fatalf("unsafe or missing startup diagnostic: %s", output.String())
	}
	output.Reset()
	err = serverFailure(logger, "check_schema", &pgconn.PgError{Code: "42501", Detail: "SECRET", Hint: "SECRET", InternalQuery: "SECRET"}, "database schema unavailable")
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), `"sqlstate":"42501"`) || !strings.Contains(output.String(), `"cause_category":"postgresql"`) {
		t.Fatalf("unsafe or missing schema diagnostic: %s", output.String())
	}
	output.Reset()
	_, _ = (safeTransportLog{logger}).Write([]byte("SECRET raw protocol diagnostic"))
	if strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), `"operation":"http_transport"`) {
		t.Fatalf("unsafe transport log: %s", output.String())
	}
}
