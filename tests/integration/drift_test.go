//go:build integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"threatservice/internal/threat"
	"threatservice/migrations"
)

func TestSchemaDriftFailsCheckAndUpWithoutRepair(t *testing.T) {
	cases := map[string]string{
		"missing table":           `DROP TABLE threats`,
		"missing column":          `ALTER TABLE threats DROP COLUMN severity`,
		"changed type":            `ALTER TABLE threats ALTER COLUMN severity TYPE text`,
		"missing not null":        `ALTER TABLE threats ALTER COLUMN description DROP NOT NULL`,
		"missing default":         `ALTER TABLE threats ALTER COLUMN updated_at DROP DEFAULT`,
		"missing primary key":     `ALTER TABLE threats DROP CONSTRAINT threats_pkey`,
		"missing check":           `ALTER TABLE threats DROP CONSTRAINT threats_severity_values`,
		"check on another column": `ALTER TABLE threats DROP CONSTRAINT threats_severity_values; ALTER TABLE threats ADD CONSTRAINT threats_severity_values CHECK (name <> '')`,
		"unvalidated check":       `ALTER TABLE threats DROP CONSTRAINT threats_description_length; ALTER TABLE threats ADD CONSTRAINT threats_description_length CHECK (char_length(description) <= 4000) NOT VALID`,
		"row level security":      `ALTER TABLE threats ENABLE ROW LEVEL SECURITY`,
		"ledger missing column":   `ALTER TABLE schema_migrations DROP COLUMN applied_at`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			pool := database(t)
			ctx := context.Background()
			if err := migrations.Check(ctx, pool); err != nil {
				t.Fatalf("baseline schema rejected: %v", err)
			}
			if _, err := pool.Exec(ctx, sql); err != nil {
				t.Fatalf("prepare schema drift: %v", err)
			}
			if err := migrations.Check(ctx, pool); err == nil {
				t.Fatal("readiness accepted a schema that no longer matches the migration")
			}
			if err := migrations.Up(ctx, pool); err == nil {
				t.Fatal("up trusted the version ledger despite schema drift")
			}
			// Refusing drift must not reset the ledger or silently recreate tables.
			var version int64
			if err := pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&version); err != nil || version != 1 {
				t.Fatalf("drift detection changed the migration version: %d, %v", version, err)
			}
		})
	}
}

func TestSearchPathDoesNotBorrowSchemaFromLaterEntry(t *testing.T) {
	base := database(t)
	ctx := context.Background()
	var schema string
	if err := base.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	front := schema + "_front"
	quoted := pgx.Identifier{front}.Sanitize()
	if _, err := base.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := base.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if _, err := repository(t, base, time.Second).Create(ctx, testMD5, sample("original schema")); err != nil {
		t.Fatal(err)
	}
	config := base.Config()
	config.ConnConfig.RuntimeParams["search_path"] = quoted + ", " + pgx.Identifier{schema}.Sanitize()
	frontPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer frontPool.Close()
	if err := migrations.Check(ctx, frontPool); err == nil {
		t.Fatal("an empty first schema borrowed the later schema's version ledger")
	}
	if err := migrations.Up(ctx, frontPool); err != nil {
		t.Fatalf("apply into first schema: %v", err)
	}
	if _, err := repository(t, frontPool, time.Second).GetByMD5(ctx, testMD5); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("new target schema borrowed a later schema's record: %v", err)
	}
	if err := migrations.Down(ctx, frontPool); err != nil {
		t.Fatal(err)
	}
	got, err := repository(t, base, time.Second).GetByMD5(ctx, testMD5)
	if err != nil || got.Name != "original schema" {
		t.Fatalf("migrating another schema changed the original one: %+v, %v", got, err)
	}
}

func TestTemporaryTablesCannotShadowMigrationTargets(t *testing.T) {
	base := database(t)
	ctx := context.Background()
	config := base.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TEMP TABLE schema_migrations (unexpected text);
		CREATE TEMP TABLE threats (unexpected text)`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Check(ctx, pool); err != nil {
		t.Fatalf("temporary relations shadowed permanent schema inspection: %v", err)
	}
	if err := migrations.Down(ctx, pool); err != nil {
		t.Fatalf("temporary relations redirected destructive migration: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_temp.threats`).Scan(&count); err != nil {
		t.Fatalf("down incorrectly dropped the temporary table: %v", err)
	}
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatalf("up failed with temporary names present: %v", err)
	}
}

func TestReadinessWaitsForMigrationLockWithinDeadline(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	locker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(ctx)
	// This is the same transaction-scoped key used by the migration runner.
	if _, err := locker.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(0x544852454154)); err != nil {
		t.Fatal(err)
	}
	if _, err := locker.Exec(ctx, `DROP TABLE threats; DELETE FROM schema_migrations`); err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	err = migrations.Check(deadline, pool)
	cancel()
	if err == nil || deadline.Err() == nil {
		t.Fatalf("readiness bypassed an unfinished migration: %v", err)
	}
	if err := locker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Check(ctx, pool); err != nil {
		t.Fatalf("readiness did not recover after migration rollback: %v", err)
	}
}

func TestCanceledQueryDoesNotCancelNextUseOfSameConnection(t *testing.T) {
	base := database(t)
	ctx := context.Background()
	if _, err := repository(t, base, time.Second).Create(ctx, testMD5, sample("initial")); err != nil {
		t.Fatal(err)
	}
	config := base.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var pid int
	if err := pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		locker, err := base.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := locker.Exec(ctx, `SELECT md5 FROM threats WHERE md5 = $1 FOR UPDATE`, testMD5); err != nil {
			_ = locker.Rollback(ctx)
			t.Fatal(err)
		}
		_, err = repository(t, pool, 60*time.Millisecond).Replace(ctx, testMD5, sample("expired"))
		_ = locker.Rollback(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("iteration %d did not cancel blocked query: %v", i, err)
		}
		var reusedPID int
		if err := pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&reusedPID); err != nil {
			t.Fatalf("late cancel reached the next query: %v", err)
		}
		if reusedPID != pid {
			t.Fatalf("healthy server cancellation should preserve the one test connection: %d != %d", reusedPID, pid)
		}
		if _, err := repository(t, pool, time.Second).Replace(ctx, testMD5, sample(fmt.Sprintf("replacement %d", i))); err != nil {
			t.Fatalf("reused connection received an earlier cancel: %v", err)
		}
	}
}

func TestReadinessRejectsMissingRuntimePrivileges(t *testing.T) {
	base := database(t)
	ctx := context.Background()
	var canCreateRole bool
	if err := base.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&canCreateRole); err != nil {
		t.Fatal(err)
	}
	if !canCreateRole {
		t.Skip("privilege regression requires a disposable test owner with CREATEROLE")
	}
	var schema string
	if err := base.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := pgx.Identifier{schema + "_reader"}.Sanitize()
	qualified := pgx.Identifier{schema}.Sanitize()
	if _, err := base.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := base.Exec(cleanup, "DROP OWNED BY "+role+"; DROP ROLE "+role); err != nil {
			t.Errorf("remove isolated test role: %v", err)
		}
	})
	// Membership permits SET ROLE also when the test owner has CREATEROLE but
	// is not a superuser; it does not give the restricted role owner rights.
	if _, err := base.Exec(ctx, "GRANT "+role+" TO CURRENT_USER; "+
		"GRANT USAGE ON SCHEMA "+qualified+" TO "+role+"; "+
		"GRANT SELECT ON "+qualified+".schema_migrations, "+qualified+".threats TO "+role); err != nil {
		t.Fatal(err)
	}
	config := base.Config()
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "SET ROLE "+role)
		return err
	}
	restricted, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	if err := migrations.Check(ctx, restricted); err == nil {
		t.Fatal("a read-only role must not pass write-service readiness")
	}
	if _, err := base.Exec(ctx, "GRANT INSERT ON "+qualified+".threats TO "+role); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Check(ctx, restricted); err == nil {
		t.Fatal("a role without UPDATE must not pass readiness")
	}
	if _, err := base.Exec(ctx, "GRANT UPDATE ON "+qualified+".threats TO "+role); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Check(ctx, restricted); err != nil {
		t.Fatalf("the documented runtime privileges must pass readiness: %v", err)
	}
	if _, err := repository(t, restricted, time.Second).Create(ctx, testMD5, sample("restricted role")); err != nil {
		t.Fatalf("documented runtime grants do not support Create: %v", err)
	}
}
