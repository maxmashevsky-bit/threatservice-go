package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		logger.Error("migration failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(args []string, lookup func(string) string, output io.Writer) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	appRole := flags.String("app-role", "", "grant runtime privileges to this existing non-owner role after up")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := fmt.Fprintln(output, "usage: migrate [-app-role=ROLE] up|down|status\ndown requires ALLOW_DESTRUCTIVE_MIGRATION=1 and removes threat data")
			return err
		}
		return fmt.Errorf("invalid arguments; usage: migrate [-app-role=ROLE] up|down|status")
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: migrate [-app-role=threat_app] up|down|status")
	}
	command := flags.Arg(0)
	if command != "up" && command != "down" && command != "status" {
		return fmt.Errorf("expected up, down or status")
	}
	if *appRole != "" && command != "up" {
		return fmt.Errorf("-app-role is only supported with up")
	}
	if command == "down" && lookup("ALLOW_DESTRUCTIVE_MIGRATION") != "1" {
		return fmt.Errorf("down removes all threat data; set ALLOW_DESTRUCTIVE_MIGRATION=1 explicitly")
	}
	dsn := lookup("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("invalid DATABASE_URL")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database unavailable")
	}
	switch command {
	case "up":
		err = migrations.Up(ctx, pool)
		if err == nil && *appRole != "" {
			if err := grantApp(ctx, pool, *appRole); err != nil {
				return fmt.Errorf("schema migration completed, but runtime-role grants failed; correct the role and rerun up")
			}
		}
	case "down":
		err = migrations.Down(ctx, pool)
	case "status":
		err = migrations.Check(ctx, pool)
	}
	if err != nil {
		return fmt.Errorf("could not complete %s; check database access and schema version", command)
	}
	_, err = fmt.Fprintf(output, "migration %s completed\n", command)
	return err
}

func grantApp(ctx context.Context, pool *pgxpool.Pool, role string) error {
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
		AND NOT pg_catalog.pg_has_role(r.oid, t.relowner, 'MEMBER')
		AND NOT pg_catalog.pg_has_role(r.oid, m.relowner, 'MEMBER')
		FROM pg_catalog.pg_roles r, pg_catalog.pg_class t, pg_catalog.pg_class m
		WHERE r.rolname=$1 AND t.oid=pg_catalog.to_regclass($2) AND m.oid=pg_catalog.to_regclass($3)`, role, table, ledger).Scan(&safe); err != nil {
		return err
	}
	if !safe {
		return fmt.Errorf("runtime role must not be privileged, own the tables or inherit their owner")
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
