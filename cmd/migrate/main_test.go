package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"threatservice/migrations"
)

func TestInvalidArgumentsFailBeforeDatabaseAccess(t *testing.T) {
	for _, args := range [][]string{nil, {"wrong"}, {"up", "status"}, {"-bad=SECRET_SENTINEL"}, {"-app-role"}, {"up", "-app-role=role"}, {"-app-role=role", "status"}, {"-app-role=role", "down"}} {
		var output bytes.Buffer
		err := run(args, func(string) string { t.Error("invalid arguments must not inspect database configuration"); return "" }, &output)
		if err == nil {
			t.Fatalf("accepted %v", args)
		}
		if strings.Contains(err.Error()+output.String(), "SECRET_SENTINEL") {
			t.Fatal("argument leaked")
		}
	}
}

type unprintableMigrationError struct{}

func (unprintableMigrationError) Error() string { panic("must not format the original error") }

func assertMigrationLog(t *testing.T, raw, operation, category, sqlstate string) {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		t.Fatalf("expected one JSON diagnostic: %v", err)
	}
	if event["level"] != "ERROR" || event["operation"] != operation || event["cause_category"] != category {
		t.Fatalf("wrong diagnostic metadata: %v", event)
	}
	if sqlstate != "" {
		if event["sqlstate"] != sqlstate {
			t.Fatalf("SQLSTATE = %v, want %s", event["sqlstate"], sqlstate)
		}
	} else if _, ok := event["sqlstate"]; ok {
		t.Fatal("SQLSTATE must be absent when PostgreSQL did not supply one")
	}
	if event["msg"] == "" || strings.Contains(raw, "SECRET") || strings.Contains(raw, "postgres://") {
		t.Fatal("missing safe message or leaked sensitive data")
	}
	for key := range event {
		switch key {
		case "time", "level", "msg", "operation", "cause_category", "sqlstate":
		default:
			t.Fatalf("unexpected diagnostic field %s", key)
		}
	}
}

func TestMigrationFailureRetainsOnlySafeMetadata(t *testing.T) {
	pg := &pgconn.PgError{Code: "42501", Message: "SECRET", Detail: "SECRET", Hint: "SECRET",
		Where: "SECRET", InternalQuery: "SECRET", SchemaName: "SECRET", TableName: "SECRET",
		ColumnName: "SECRET", ConstraintName: "SECRET"}
	for _, tc := range []struct {
		name, operation, category, sqlstate string
		err                                 error
	}{
		{"opaque", "apply_migration", "internal", "", unprintableMigrationError{}},
		{"cancel", "apply_migration", "context_canceled", "", context.Canceled},
		{"deadline", "apply_migration", "deadline_exceeded", "57014", errors.Join(context.DeadlineExceeded, &pgconn.PgError{Code: "57014", Message: "SECRET"})},
		{"connection", "connect_database", "database_unavailable", "08006", &pgconn.PgError{Code: "08006", Detail: "SECRET"}},
		{"password", "connect_database", "authentication_failed", "28P01", &pgconn.PgError{Code: "28P01", Detail: "SECRET"}},
		{"postgres", "apply_migration", "postgresql", "42501", fmt.Errorf("SECRET: %w", pg)},
		{"schema query", "check_schema", "postgresql", "42501", &migrations.CheckError{Err: pg}},
		{"schema mismatch", "check_schema", "schema_mismatch", "", &migrations.CheckError{Err: fmt.Errorf("%w: SECRET", migrations.ErrSchemaMismatch)}},
		{"missing role", "grant_runtime_role", "runtime_role_missing", "", errRuntimeRoleMissing},
		{"unsafe role", "grant_runtime_role", "runtime_role_unsafe", "", errRuntimeRoleUnsafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			operation := tc.operation
			if strings.HasPrefix(tc.name, "schema") {
				operation = "apply_migration"
			}
			err := migrationFailure(slog.New(slog.NewJSONHandler(&output, nil)), operation, tc.err, "migration failed safely")
			if err.Error() != "migration failed safely" {
				t.Fatal("returned an unsafe error")
			}
			assertMigrationLog(t, output.String(), tc.operation, tc.category, tc.sqlstate)
		})
	}
}

func TestMalformedMigrationDSNIsNotLogged(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{"up"}, func(key string) string {
		if key == "DATABASE_URL" {
			return "postgres://SECRET:SECRET%zz@localhost/SECRET"
		}
		return ""
	}, &output)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("expected a safe configuration error")
	}
	assertMigrationLog(t, output.String(), "parse_database_config", "configuration", "")
}

func TestDestructiveGuardPrecedesDatabaseConnection(t *testing.T) {
	err := run([]string{"down"}, func(k string) string {
		if k == "DATABASE_URL" {
			t.Fatal("unguarded down attempted to use database configuration")
		}
		return ""
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "ALLOW_DESTRUCTIVE_MIGRATION=1") {
		t.Fatalf("got %v", err)
	}
}

func TestMigrationHelpAndMissingConfiguration(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"-h"}, func(string) string { t.Fatal("help requested configuration"); return "" }, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "up|down|status") {
		t.Fatal("help does not describe commands")
	}
	if err := run([]string{"up"}, func(string) string { return "" }, &bytes.Buffer{}); err == nil || err.Error() != "DATABASE_URL is required" {
		t.Fatalf("got %v", err)
	}
}
