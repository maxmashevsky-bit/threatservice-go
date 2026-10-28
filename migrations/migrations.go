// Package migrations embeds the versioned schema and applies it transactionally.
package migrations

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const Version int64 = 1

var ErrSchemaMismatch = errors.New("schema does not match the service migration")

// CheckError marks validation failures without losing a driver error or SQLSTATE.
type CheckError struct{ Err error }

func (e *CheckError) Error() string { return e.Err.Error() }
func (e *CheckError) Unwrap() error { return e.Err }

func schemaCheck(err error) error {
	if err == nil {
		return nil
	}
	return &CheckError{Err: err}
}

func incompatibleSchema(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSchemaMismatch, fmt.Sprintf(format, args...))
}

// All runners for this service use the same transaction-scoped lock. Applying
// migrations in different test schemas may serialize briefly, which is harmless.
const migrationLock int64 = 0x544852454154

//go:embed *.sql
var files embed.FS

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Up applies pending migrations exactly once, including the version ledger.
func Up(ctx context.Context, pool *pgxpool.Pool) error {
	return withLock(ctx, pool, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY CHECK (version > 0),
			applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			return fmt.Errorf("create migration ledger: %w", err)
		}
		versions, err := readVersions(ctx, tx)
		if err != nil {
			return schemaCheck(err)
		}
		if len(versions) == 1 && versions[0] == Version {
			return schemaCheck(checkSchema(ctx, tx))
		}
		if len(versions) != 0 {
			return schemaCheck(incompatibleSchema("unsupported migration versions: %v; expected empty or [%d]", versions, Version))
		}
		sql, err := files.ReadFile("001_threats.up.sql")
		if err != nil {
			return fmt.Errorf("read embedded migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("apply migration %d: %w", Version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, Version); err != nil {
			return fmt.Errorf("record migration: %w", err)
		}
		return schemaCheck(checkSchema(ctx, tx))
	})
}

// Down removes the current schema and its data. The empty ledger remains so Up
// can apply the migration again. Application shutdown must never call Down.
func Down(ctx context.Context, pool *pgxpool.Pool) error {
	return withLock(ctx, pool, false, func(tx pgx.Tx) error {
		if err := check(ctx, tx); err != nil {
			return schemaCheck(err)
		}
		sql, err := files.ReadFile("001_threats.down.sql")
		if err != nil {
			return fmt.Errorf("read embedded down migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("revert migration %d: %w", Version, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, Version); err != nil {
			return fmt.Errorf("remove migration version: %w", err)
		}
		return nil
	})
}

// Check is read-only and is safe for the restricted application role. That role
// needs SELECT on schema_migrations in addition to its threat-table grants.
func Check(ctx context.Context, pool *pgxpool.Pool) error {
	return withLock(ctx, pool, true, func(tx pgx.Tx) error { return schemaCheck(check(ctx, tx)) })
}

func check(ctx context.Context, q querier) error {
	versions, err := readVersions(ctx, q)
	if err != nil {
		return err
	}
	if len(versions) != 1 || versions[0] != Version {
		return incompatibleSchema("schema version mismatch: got %v, expected [%d]", versions, Version)
	}
	return checkSchema(ctx, q)
}

func readVersions(ctx context.Context, q querier) ([]int64, error) {
	rows, err := q.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()
	var versions []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("decode migration version: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read migration versions: %w", err)
	}
	return versions, nil
}

func withLock(ctx context.Context, pool *pgxpool.Pool, readOnly bool, action func(pgx.Tx) error) error {
	options := pgx.TxOptions{}
	if readOnly {
		options.AccessMode = pgx.ReadOnly
	}
	tx, err := pool.BeginTx(ctx, options)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() {
		// Cleanup must still run after cancellation of the caller's context.
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	lock := `SELECT pg_catalog.pg_advisory_xact_lock($1)`
	if readOnly {
		lock = `SELECT pg_catalog.pg_advisory_xact_lock_shared($1)`
	}
	if _, err := tx.Exec(ctx, lock, migrationLock); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	var schema *string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_schema()`).Scan(&schema); err != nil {
		return fmt.Errorf("resolve migration schema: %w", err)
	}
	if schema == nil {
		return fmt.Errorf("search_path does not contain an accessible target schema")
	}
	// Never resolve half of the service's tables in a later search_path schema.
	// Put pg_temp last so a temporary relation cannot shadow permanent tables.
	path := pgx.Identifier{*schema}.Sanitize() + ", pg_temp"
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('search_path', $1, true)`, path); err != nil {
		return fmt.Errorf("pin migration schema: %w", err)
	}
	if err := action(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
