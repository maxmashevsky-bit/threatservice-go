// Package postgres stores current threat records in PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"threatservice/internal/threat"
)

// Repository bounds both waiting for a pooled connection and executing SQL.
type Repository struct {
	pool         *pgxpool.Pool
	queryTimeout time.Duration
	table        string
}

var _ threat.Repository = (*Repository)(nil)

func New(pool *pgxpool.Pool, queryTimeout time.Duration, schema string) *Repository {
	if queryTimeout <= 0 {
		queryTimeout = 2 * time.Second
	}
	return &Repository{pool: pool, queryTimeout: queryTimeout, table: pgx.Identifier{schema, "threats"}.Sanitize()}
}

func (r *Repository) Create(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()
	result, err := scan(r.pool.QueryRow(ctx, `
		INSERT INTO `+r.table+` (md5, name, description, severity)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (md5) DO NOTHING
		RETURNING md5, name, description, severity, created_at, updated_at`,
		md5, input.Name, input.Description, string(input.Severity)))
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrAlreadyExists
	}
	if err != nil {
		return threat.Threat{}, queryError(ctx, "create threat", err)
	}
	return result, nil
}

func (r *Repository) GetByMD5(ctx context.Context, md5 string) (threat.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()
	result, err := scan(r.pool.QueryRow(ctx, `
		SELECT md5, name, description, severity, created_at, updated_at
		FROM `+r.table+` WHERE md5 = $1`, md5))
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrNotFound
	}
	if err != nil {
		return threat.Threat{}, queryError(ctx, "get threat", err)
	}
	return result, nil
}

func (r *Repository) Replace(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()
	result, err := scan(r.pool.QueryRow(ctx, `
		UPDATE `+r.table+`
		SET name = $2,
		    description = $3,
		    severity = $4,
		    updated_at = CASE
		      WHEN (name, description, severity)
		           IS DISTINCT FROM ($2::varchar, $3::text, $4::varchar)
		      THEN GREATEST(statement_timestamp(), updated_at)
		      ELSE updated_at
		    END
		WHERE md5 = $1
		RETURNING md5, name, description, severity, created_at, updated_at`,
		md5, input.Name, input.Description, string(input.Severity)))
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrNotFound
	}
	if err != nil {
		return threat.Threat{}, queryError(ctx, "replace threat", err)
	}
	return result, nil
}

func queryError(ctx context.Context, operation string, err error) error {
	// A server-acknowledged cancellation is a PostgreSQL error (57014), while a
	// local timeout may wrap context.DeadlineExceeded. Preserve both causes.
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func scan(row pgx.Row) (threat.Threat, error) {
	var result threat.Threat
	var severity string
	// Scan also consumes the command result and releases the pooled connection.
	if err := row.Scan(&result.MD5, &result.Name, &result.Description,
		&severity, &result.CreatedAt, &result.UpdatedAt); err != nil {
		return threat.Threat{}, err
	}
	result.Severity = threat.Severity(severity)
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}
