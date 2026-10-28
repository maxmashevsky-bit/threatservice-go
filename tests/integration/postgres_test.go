//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"threatservice/internal/postgres"
	"threatservice/internal/threat"
	"threatservice/migrations"
)

const testMD5 = "0123456789abcdef0123456789abcdef"

// Every test creates and drops only its own random schema. TEST_DATABASE_URL
// must identify a disposable test database with permission to create schemas.
// A supplied but unusable URL is a failure, never a skipped integration run.
func database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run against a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("parse test database configuration: %v", err)
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "threat_it_" + hex.EncodeToString(random[:])
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("remove isolated test schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = identifier
	config.MaxConns = 20
	postgres.ConfigurePool(config)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func sample(name string) threat.Input {
	return threat.Input{Name: name, Description: "Описание " + name, Severity: threat.SeverityHigh}
}

func sameInput(got threat.Threat, want threat.Input) bool {
	return got.Name == want.Name && got.Description == want.Description && got.Severity == want.Severity
}

func TestRepositoryCreateGetReplace(t *testing.T) {
	pool := database(t)
	repo := repository(t, pool, 2*time.Second)
	ctx := context.Background()
	initial := sample("Trojan.Win32.Generic")
	created, err := repo.Create(ctx, testMD5, initial)
	if err != nil {
		t.Fatal(err)
	}
	if created.MD5 != testMD5 || !sameInput(created, initial) || created.CreatedAt.IsZero() || !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("unexpected created record: %+v", created)
	}
	if _, err := repo.Create(ctx, testMD5, sample("Must not overwrite")); !errors.Is(err, threat.ErrAlreadyExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	read, err := repo.GetByMD5(ctx, testMD5)
	if err != nil || !sameInput(read, initial) || !read.UpdatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("duplicate changed current record: %+v, %v", read, err)
	}
	unchanged, err := repo.Replace(ctx, testMD5, initial)
	if err != nil || !unchanged.UpdatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("identical replacement changed updated_at: %+v, %v", unchanged, err)
	}
	replacement := threat.Input{Name: "Обновлено", Severity: threat.SeverityUnknown}
	updated, err := repo.Replace(ctx, testMD5, replacement)
	if err != nil || !sameInput(updated, replacement) || !updated.CreatedAt.Equal(created.CreatedAt) || updated.UpdatedAt.Before(created.UpdatedAt) {
		t.Fatalf("unexpected replacement: %+v, %v", updated, err)
	}
	// A new connection pool must read the same durable state.
	otherPool, err := pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer otherPool.Close()
	persisted, err := repository(t, otherPool, time.Second).GetByMD5(ctx, testMD5)
	if err != nil || !sameInput(persisted, replacement) || !persisted.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Fatalf("new pool could not read persisted record: %+v, %v", persisted, err)
	}
	missing := strings.Repeat("f", 32)
	if _, err := repo.GetByMD5(ctx, missing); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing get: %v", err)
	}
	if _, err := repo.Replace(ctx, missing, initial); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing replace: %v", err)
	}
}

func TestConcurrentCreateHasOneWinner(t *testing.T) {
	pool := database(t)
	repo := repository(t, pool, 5*time.Second)
	start := make(chan struct{})
	results := make(chan error, 20)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := repo.Create(context.Background(), testMD5, sample("Winner"))
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	winners, duplicates := 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, threat.ErrAlreadyExists):
			duplicates++
		default:
			t.Errorf("unexpected concurrent create error: %v", err)
		}
	}
	if winners != 1 || duplicates != 19 {
		t.Fatalf("got %d winners and %d duplicates", winners, duplicates)
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM threats`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected one stored row, got %d: %v", count, err)
	}
}

func TestConcurrentReplaceAndGetNeverMixFields(t *testing.T) {
	pool := database(t)
	repo := repository(t, pool, 5*time.Second)
	inputs := []threat.Input{
		{Name: "A", Description: "description A", Severity: threat.SeverityLow},
		{Name: "B", Description: "description B", Severity: threat.SeverityCritical},
	}
	created, err := repo.Create(context.Background(), testMD5, inputs[0])
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	problems := make(chan error, 1000)
	var group sync.WaitGroup
	for writer := 0; writer < 8; writer++ {
		input := inputs[writer%len(inputs)]
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for i := 0; i < 25; i++ {
				got, err := repo.Replace(context.Background(), testMD5, input)
				if err != nil || !sameInput(got, input) || !got.CreatedAt.Equal(created.CreatedAt) {
					problems <- fmt.Errorf("replace returned %+v: %v", got, err)
				}
			}
		}()
	}
	for reader := 0; reader < 3; reader++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for i := 0; i < 100; i++ {
				got, err := repo.GetByMD5(context.Background(), testMD5)
				if err != nil || (!sameInput(got, inputs[0]) && !sameInput(got, inputs[1])) || !got.CreatedAt.Equal(created.CreatedAt) {
					problems <- fmt.Errorf("get observed mixed record %+v: %v", got, err)
				}
			}
		}()
	}
	close(start)
	group.Wait()
	close(problems)
	for err := range problems {
		t.Error(err)
	}
	final, err := repo.GetByMD5(context.Background(), testMD5)
	if err != nil || (!sameInput(final, inputs[0]) && !sameInput(final, inputs[1])) {
		t.Fatalf("unexpected final record: %+v, %v", final, err)
	}
}

func TestUncommittedCreateIsInvisibleToGetAndReplace(t *testing.T) {
	pool := database(t)
	repo := repository(t, pool, time.Second)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO threats (md5, name) VALUES ($1, 'pending')`, testMD5); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByMD5(ctx, testMD5); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("GET saw an uncommitted insert: %v", err)
	}
	if _, err := repo.Replace(ctx, testMD5, sample("must not create")); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("PUT should not see or create the pending row: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByMD5(ctx, testMD5)
	if err != nil || got.Name != "pending" {
		t.Fatalf("committed create unavailable: %+v, %v", got, err)
	}
}

func TestBlockedReplaceTimesOutWithoutDelayedWrite(t *testing.T) {
	pool := database(t)
	repo := repository(t, pool, 100*time.Millisecond)
	ctx := context.Background()
	initial := sample("original")
	if _, err := repo.Create(ctx, testMD5, initial); err != nil {
		t.Fatal(err)
	}
	locker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(ctx)
	// The lock is acquired synchronously before Replace is started; no sleep is needed.
	if _, err := locker.Exec(ctx, `SELECT md5 FROM threats WHERE md5 = $1 FOR UPDATE`, testMD5); err != nil {
		t.Fatal(err)
	}
	_, err = repo.Replace(ctx, testMD5, sample("expired"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline while waiting for row lock, got %v", err)
	}
	if err := locker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := repository(t, pool, time.Second).GetByMD5(ctx, testMD5)
	if err != nil || !sameInput(got, initial) {
		t.Fatalf("timed-out replacement committed later: %+v, %v", got, err)
	}
	if _, err := repository(t, pool, time.Second).Replace(ctx, testMD5, sample("recovered")); err != nil {
		t.Fatalf("pool did not recover after cancellation: %v", err)
	}
}

func TestQueryTimeoutIncludesWaitingForPool(t *testing.T) {
	pool := database(t)
	config := pool.Config()
	config.MaxConns = 1
	single, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer single.Close()
	repo := repository(t, single, 100*time.Millisecond)
	connection, err := single.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	_, err = repo.GetByMD5(context.Background(), testMD5)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool acquisition did not respect query timeout: %v", err)
	}
	connection.Release()
	_, err = repository(t, single, time.Second).GetByMD5(context.Background(), testMD5)
	if !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("pool unavailable after canceled acquisition: %v", err)
	}
}

func TestMigrationsAreVersionedAndReversible(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatalf("repeated up must be harmless: %v", err)
	}
	if err := migrations.Check(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := repository(t, pool, time.Second).Create(ctx, testMD5, sample("will be deleted")); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Down(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Check(ctx, pool); err == nil {
		t.Fatal("empty migration ledger must fail startup check")
	}
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := repository(t, pool, time.Second).GetByMD5(ctx, testMD5); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("down/up unexpectedly preserved deleted data: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES (99)`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Check(ctx, pool); err == nil {
		t.Fatal("unknown schema version must fail startup check")
	}
	if err := migrations.Up(ctx, pool); err == nil {
		t.Fatal("up must refuse an unknown migration version")
	}
}

func TestConcurrentMigrationsApplyOnce(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	if err := migrations.Down(ctx, pool); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 8)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- migrations.Up(ctx, pool)
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("concurrent migration failed: %v", err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected one migration ledger entry, got %d: %v", count, err)
	}
}

func TestFailedMigrationDoesNotRecordVersion(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	if err := migrations.Down(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// An incompatible preexisting table deliberately makes the embedded DDL fail.
	if _, err := pool.Exec(ctx, `CREATE TABLE threats (unexpected integer)`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pool); err == nil {
		t.Fatal("migration should reject an incompatible existing object")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed migration was recorded: %d, %v", count, err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE threats`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatalf("failed migration could not be retried after fixing the cause: %v", err)
	}
}

func TestDatabaseConstraintsRejectInvalidRows(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	cases := []struct {
		name, query string
		args        []any
	}{
		{"uppercase MD5", `INSERT INTO threats (md5, name) VALUES ($1, 'x')`, []any{strings.Repeat("A", 32)}},
		{"short MD5", `INSERT INTO threats (md5, name) VALUES ('abc', 'x')`, nil},
		{"null name", `INSERT INTO threats (md5, name) VALUES ($1, NULL)`, []any{testMD5}},
		{"blank name", `INSERT INTO threats (md5, name) VALUES ($1, '   ')`, []any{testMD5}},
		{"long name", `INSERT INTO threats (md5, name) VALUES ($1, $2)`, []any{testMD5, strings.Repeat("я", 256)}},
		{"long description", `INSERT INTO threats (md5, name, description) VALUES ($1, 'x', $2)`, []any{testMD5, strings.Repeat("я", 4001)}},
		{"unknown severity", `INSERT INTO threats (md5, name, severity) VALUES ($1, 'x', 'fatal')`, []any{testMD5}},
		{"backwards timestamps", `INSERT INTO threats (md5, name, created_at, updated_at) VALUES ($1, 'x', '2026-10-28T12:00:00Z', '2026-10-28T11:00:00Z')`, []any{testMD5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.query, tc.args...); err == nil {
				t.Fatal("invalid row accepted")
			}
		})
	}
	input := threat.Input{Name: strings.Repeat("я", 255), Description: strings.Repeat("я", 4000), Severity: threat.SeverityUnknown}
	if _, err := repository(t, pool, time.Second).Create(ctx, testMD5, input); err != nil {
		t.Fatalf("Unicode values at length boundary must pass: %v", err)
	}
}

func repository(t *testing.T, pool *pgxpool.Pool, timeout time.Duration) *postgres.Repository {
	t.Helper()
	var schema string
	if err := pool.QueryRow(context.Background(), `SELECT pg_catalog.current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	return postgres.New(pool, timeout, schema)
}
