//go:build integration

package main

import (
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
	schema, role := prefix+`"schema`, prefix+`"app`
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
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", quotedSchema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path='" + quotedSchema + "'"
	}
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
	if err := run(args, lookup, io.Discard); err == nil || !strings.Contains(err.Error(), "schema migration completed") {
		t.Fatalf("missing runtime role must report a completed schema and failed grants: %v", err)
	}
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
