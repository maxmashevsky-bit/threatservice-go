//go:build integration

package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/migrations"
)

func TestRuntimeNeverFallsBackAfterTargetDisappears(t *testing.T) {
	base := database(t)
	ctx := context.Background()
	var schema string
	if err := base.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	fallback := schema + "_fallback"
	if _, err := base.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{fallback}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := base.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{fallback}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error(err)
		}
	})
	config := base.Config()
	config.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{fallback}.Sanitize()
	other, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := migrations.Up(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := repository(t, other, time.Second).Create(ctx, testMD5, sample("must never be returned")); err != nil {
		t.Fatal(err)
	}
	config = base.Config()
	config.MaxConns = 1
	config.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize() + ", " + pgx.Identifier{fallback}.Sanitize()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repo := repository(t, pool, time.Second)
	if _, err := base.Exec(ctx, "DROP TABLE threats"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByMD5(ctx, testMD5); err == nil {
		t.Fatal("runtime returned a record from the fallback schema")
	}
	if _, err := pool.Exec(ctx, "CREATE TEMP TABLE threats AS SELECT * FROM "+pgx.Identifier{fallback, "threats"}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByMD5(ctx, testMD5); err == nil {
		t.Fatal("runtime returned a record from a temporary table")
	}
	if _, err := base.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		t.Fatal(err)
	}
	// Always restore an empty schema so the fixture can remove its own schema.
	defer func() {
		if _, err := base.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
			t.Error(err)
		}
	}()
	pool.Reset()
	if _, err := repo.GetByMD5(ctx, testMD5); err == nil {
		t.Fatal("reconnecting changed the permanent target")
	}
	if err := migrations.Check(ctx, pool); err == nil {
		t.Fatal("readiness accepted the fallback after dropping its target schema")
	}
}
