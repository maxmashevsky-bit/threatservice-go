//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/migrations"
)

func TestRuntimeGrantsUseTargetSchemaAndRecoverAfterMissingRole(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for migration CLI integration checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var canCreateRole bool
	if err := admin.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&canCreateRole); err != nil {
		t.Fatal(err)
	}
	if !canCreateRole {
		t.Skip("runtime-role regression requires an isolated test owner with CREATEROLE")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "threat_cli_" + hex.EncodeToString(random[:])
	schema, role := prefix+`"SECRET_schema`, prefix+`"SECRET_app`
	quotedSchema, quotedRole := pgx.Identifier{schema}.Sanitize(), pgx.Identifier{role}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	dsn = migrationTestDSN(t, dsn, map[string]string{"search_path": quotedSchema})
	lookup := func(key string) string {
		if key == "DATABASE_URL" {
			return dsn
		}
		return ""
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	args := []string{"-app-role=" + role, "up"}
	var output bytes.Buffer
	if err := run(args, lookup, &output); err == nil || !strings.Contains(err.Error(), "schema migration completed") {
		t.Fatalf("missing runtime role must report a completed schema and failed grants: %v", err)
	}
	assertMigrationLog(t, output.String(), "grant_runtime_role", "runtime_role_missing", "")
	if err := migrations.Check(ctx, pool); err != nil {
		t.Fatalf("grant failure damaged the successful migration: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE ROLE "+quotedRole+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP OWNED BY "+quotedRole+"; DROP ROLE "+quotedRole); err != nil {
			t.Error(err)
		}
	}()
	if err := run(args, lookup, io.Discard); err != nil {
		t.Fatalf("up did not recover after creating the missing runtime role: %v", err)
	}
	var usage, read, insert, update, deleteRows, ledgerWrite bool
	err = admin.QueryRow(ctx, `SELECT pg_catalog.has_schema_privilege($1, $2, 'USAGE'),
		pg_catalog.has_table_privilege($1, $3, 'SELECT'),
		pg_catalog.has_table_privilege($1, $3, 'INSERT'),
		pg_catalog.has_table_privilege($1, $3, 'UPDATE'),
		pg_catalog.has_table_privilege($1, $3, 'DELETE'),
		pg_catalog.has_table_privilege($1, $4, 'INSERT')`, role, schema,
		pgx.Identifier{schema, "threats"}.Sanitize(), pgx.Identifier{schema, "schema_migrations"}.Sanitize()).
		Scan(&usage, &read, &insert, &update, &deleteRows, &ledgerWrite)
	if err != nil {
		t.Fatal(err)
	}
	if !usage || !read || !insert || !update || deleteRows || ledgerWrite {
		t.Fatalf("unexpected grants: usage=%v read=%v insert=%v update=%v delete=%v ledgerWrite=%v", usage, read, insert, update, deleteRows, ledgerWrite)
	}
	var owner string
	if err := admin.QueryRow(ctx, `SELECT current_user`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := grantApp(ctx, pool, owner); err == nil {
		t.Fatal("grantApp accepted the table owner as a restricted runtime role")
	}
}

func migrationTestDSN(t *testing.T, dsn string, parameters map[string]string) string {
	t.Helper()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid integration database URL")
		}
		q := u.Query()
		for key, value := range parameters {
			if key == "password" {
				username := u.User.Username()
				if username == "" {
					config, err := pgxpool.ParseConfig(dsn)
					if err != nil {
						t.Fatal("invalid integration database configuration")
					}
					username = config.ConnConfig.User
				}
				u.User = url.UserPassword(username, value)
				q.Del("password")
			} else {
				q.Set(key, value)
			}
		}
		u.RawQuery = q.Encode()
		return u.String()
	}
	for key, value := range parameters {
		value = strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `'`, `\'`)
		dsn += " " + key + "='" + value + "'"
	}
	return dsn
}

func TestMigrationDiagnosticsAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for migration diagnostics")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid integration database configuration")
	}
	defer admin.Close()
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "threat_diagnostics_SECRET_" + hex.EncodeToString(random[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	dsn = migrationTestDSN(t, dsn, map[string]string{"search_path": quoted})
	lookup := func(key string) string {
		if key == "DATABASE_URL" {
			return dsn
		}
		return ""
	}
	if err := run([]string{"up"}, lookup, io.Discard); err != nil {
		t.Fatal(err)
	}
	t.Run("wrong password", func(t *testing.T) {
		badDSN := migrationTestDSN(t, dsn, map[string]string{"password": "SECRET_wrong_password_" + hex.EncodeToString(random[:])})
		var output bytes.Buffer
		err := run([]string{"status"}, func(key string) string {
			if key == "DATABASE_URL" {
				return badDSN
			}
			return ""
		}, &output)
		if err == nil {
			t.Fatal("incorrect password was accepted; this check requires password authentication")
		}
		assertMigrationLog(t, output.String(), "connect_database", "authentication_failed", "28P01")
	})
	t.Run("incompatible schema", func(t *testing.T) {
		if _, err := admin.Exec(ctx, "ALTER TABLE "+quoted+`.threats ADD COLUMN "SECRET_column" text`); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"status", "up", "down"} {
			var output bytes.Buffer
			err := run([]string{command}, func(key string) string {
				if key == "ALLOW_DESTRUCTIVE_MIGRATION" {
					return "1"
				}
				return lookup(key)
			}, &output)
			if err == nil {
				t.Fatalf("%s accepted an incompatible schema", command)
			}
			assertMigrationLog(t, output.String(), "check_schema", "schema_mismatch", "")
		}
		if _, err := admin.Exec(ctx, "ALTER TABLE "+quoted+`.threats DROP COLUMN "SECRET_column"`); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"status"}, lookup, io.Discard); err != nil {
			t.Fatal("schema validation did not recover after repair")
		}
	})
	t.Run("migration SQL failure", func(t *testing.T) {
		if _, err := admin.Exec(ctx, "DELETE FROM "+quoted+".schema_migrations"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := run([]string{"up"}, lookup, &output); err == nil {
			t.Fatal("up accepted an existing table without a recorded migration")
		}
		assertMigrationLog(t, output.String(), "apply_migration", "postgresql", "42P07")
	})
}
