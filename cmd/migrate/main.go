// Command migrate applies explicit, transactional schema changes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/internal/diagnostic"
	"threatservice/migrations"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func run(args []string, lookup func(string) string, output io.Writer) error {
	logger := slog.New(slog.NewJSONHandler(output, nil))
	ctx := context.Background()
	fail := func(operation string, cause error, message string) error {
		if ctx.Err() != nil {
			cause = errors.Join(cause, ctx.Err())
		}
		return migrationFailure(logger, operation, cause, message)
	}
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	appRole := flags.String("app-role", "", "grant runtime privileges to this existing non-owner role after up")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := fmt.Fprintln(output, "usage: migrate [-app-role=ROLE] up|down|status\ndown requires ALLOW_DESTRUCTIVE_MIGRATION=1 and removes threat data")
			if err != nil {
				return fail("write_output", err, "could not write migration help")
			}
			return nil
		}
		return fail("validate_arguments", err, "invalid arguments; usage: migrate [-app-role=ROLE] up|down|status")
	}
	if flags.NArg() != 1 {
		return fail("validate_arguments", nil, "usage: migrate [-app-role=threat_app] up|down|status")
	}
	command := flags.Arg(0)
	if command != "up" && command != "down" && command != "status" {
		return fail("validate_arguments", nil, "expected up, down or status")
	}
	if *appRole != "" && command != "up" {
		return fail("validate_arguments", nil, "-app-role is only supported with up")
	}
	if command == "down" && lookup("ALLOW_DESTRUCTIVE_MIGRATION") != "1" {
		return fail("validate_arguments", nil, "down removes all threat data; set ALLOW_DESTRUCTIVE_MIGRATION=1 explicitly")
	}
	dsn := lookup("DATABASE_URL")
	if dsn == "" {
		return fail("parse_database_config", nil, "DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fail("parse_database_config", err, "invalid DATABASE_URL")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fail("connect_database", err, "could not connect to database; check credentials and availability")
	}
	operation := "apply_migration"
	switch command {
	case "up":
		err = migrations.Up(ctx, pool)
		if err == nil && *appRole != "" {
			if err := grantApp(ctx, pool, *appRole); err != nil {
				return fail("grant_runtime_role", err, "schema migration completed, but runtime-role grants failed; correct the role and rerun up")
			}
		}
	case "down":
		operation = "revert_migration"
		err = migrations.Down(ctx, pool)
	case "status":
		operation = "check_schema"
		err = migrations.Check(ctx, pool)
	}
	if err != nil {
		return fail(operation, err, "could not complete migration command; check database access and schema version")
	}
	_, err = fmt.Fprintf(output, "migration %s completed\n", command)
	if err != nil {
		return fail("write_output", err, "migration completed, but could not write completion message")
	}
	return nil
}

var errRuntimeRoleMissing = errors.New("runtime role does not exist")
var errRuntimeRoleUnsafe = errors.New("runtime role is privileged or inherits the table owner")

func migrationFailure(logger *slog.Logger, operation string, cause error, message string) error {
	var check *migrations.CheckError
	if errors.As(cause, &check) {
		operation = "check_schema"
	}
	category, sqlstate := diagnostic.Cause(cause)
	switch {
	case category == "context_canceled" || category == "deadline_exceeded":
	case errors.Is(cause, migrations.ErrSchemaMismatch):
		category = "schema_mismatch"
	case errors.Is(cause, errRuntimeRoleMissing):
		category = "runtime_role_missing"
	case errors.Is(cause, errRuntimeRoleUnsafe):
		category = "runtime_role_unsafe"
	case strings.HasPrefix(sqlstate, "28"):
		category = "authentication_failed"
	case operation == "validate_arguments" || operation == "parse_database_config":
		category = "configuration"
	}
	attrs := []any{"operation", operation, "cause_category", category}
	if sqlstate != "" {
		attrs = append(attrs, "sqlstate", sqlstate)
	}
	logger.Error(message, attrs...)
	return errors.New(message)
}

func grantApp(ctx context.Context, pool *pgxpool.Pool, role string) error {
	// Quote identifiers through the driver; never interpolate an untrusted role name.
	quoted := pgx.Identifier{role}.Sanitize()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var schema string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_schema()`).Scan(&schema); err != nil {
		return err
	}
	table := pgx.Identifier{schema, "threats"}.Sanitize()
	ledger := pgx.Identifier{schema, "schema_migrations"}.Sanitize()
	var safe bool
	if err := tx.QueryRow(ctx, `SELECT NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
		AND NOT pg_catalog.pg_has_role(r.oid, (SELECT relowner FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass($2)), 'MEMBER')
		AND NOT pg_catalog.pg_has_role(r.oid, (SELECT relowner FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass($3)), 'MEMBER')
		FROM pg_catalog.pg_roles r WHERE r.rolname=$1`, role, table, ledger).Scan(&safe); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errRuntimeRoleMissing
		}
		return err
	}
	if !safe {
		return errRuntimeRoleUnsafe
	}
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + quoted,
		"GRANT SELECT, INSERT, UPDATE ON TABLE " + table + " TO " + quoted,
		"GRANT SELECT ON TABLE " + ledger + " TO " + quoted,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
