//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/internal/config"
	"threatservice/internal/postgres"
	"threatservice/internal/threat"
	"threatservice/migrations"
)

type lifecycleEvent struct{ message, address string }
type lifecycleLog struct{ events chan lifecycleEvent }

func (h lifecycleLog) Enabled(context.Context, slog.Level) bool { return true }
func (h lifecycleLog) Handle(_ context.Context, r slog.Record) error {
	e := lifecycleEvent{message: r.Message}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "address" {
			e.address = a.Value.String()
		}
		return true
	})
	select {
	case h.events <- e:
	default:
	}
	return nil
}
func (h lifecycleLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h lifecycleLog) WithGroup(string) slog.Handler      { return h }

func lifecycleDatabase(t *testing.T) (*pgxpool.Pool, config.Config, string) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for server lifecycle checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "threat_server_" + hex.EncodeToString(random[:])
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	postgres.ConfigurePool(pc)
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DatabaseURL: dsn, HTTPAddr: "127.0.0.1:0", PGMaxConns: 4, RequestTimeout: 2 * time.Second, QueryTimeout: time.Second, ShutdownTimeout: time.Second}
	return pool, cfg, schema
}

func startLifecycleServer(t *testing.T, cfg config.Config) (string, context.CancelFunc, <-chan struct{}, *error, <-chan lifecycleEvent) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	events := make(chan lifecycleEvent, 16)
	done := make(chan struct{})
	var result error
	go func() { result = run(ctx, cfg, slog.New(lifecycleLog{events})); close(done) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server did not finish cleanup")
		}
	})
	for {
		select {
		case event := <-events:
			if event.message == "server started" {
				return "http://" + event.address, stop, done, &result, events
			}
		case <-done:
			t.Fatalf("server failed before startup: %v", result)
		case <-time.After(6 * time.Second):
			t.Fatal("server startup timed out")
		}
	}
}

func waitForSQLLock(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name='threatservice' AND wait_event_type='Lock' AND query LIKE '%UPDATE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == want {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("SQL lock state did not become %v", want)
		}
	}
}

func TestServerDrainsOrCancelsActiveSQLWithinShutdownBudget(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(fmt.Sprintf("forced=%v", forced), func(t *testing.T) {
			pool, cfg, schema := lifecycleDatabase(t)
			if forced {
				cfg.ShutdownTimeout = 50 * time.Millisecond
			}
			repo := postgres.New(pool, time.Second, schema)
			hash := strings.Repeat("a", 32)
			if _, err := repo.Create(context.Background(), hash, threat.Input{Name: "initial", Severity: threat.SeverityUnknown}); err != nil {
				t.Fatal(err)
			}
			locker, err := pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer locker.Rollback(context.Background())
			if _, err := locker.Exec(context.Background(), `SELECT md5 FROM threats WHERE md5=$1 FOR UPDATE`, hash); err != nil {
				t.Fatal(err)
			}
			base, stop, done, result, events := startLifecycleServer(t, cfg)
			response := make(chan int, 1)
			go func() {
				req, _ := http.NewRequest(http.MethodPut, base+"/info/"+hash, strings.NewReader(`{"name":"replacement"}`))
				req.Header.Set("Content-Type", "application/json")
				client := &http.Client{Timeout: 3 * time.Second}
				r, err := client.Do(req)
				if err != nil {
					response <- 0
					return
				}
				defer r.Body.Close()
				_, _ = io.Copy(io.Discard, r.Body)
				response <- r.StatusCode
			}()
			waitForSQLLock(t, pool, true)
			started := time.Now()
			stop()
			for {
				event := <-events
				if event.message == "server stopping" {
					break
				}
			}
			if !forced {
				if err := locker.Rollback(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("shutdown exceeded its budget")
			}
			if forced {
				if *result == nil || time.Since(started) > time.Second {
					t.Fatalf("forced shutdown: result=%v elapsed=%v", *result, time.Since(started))
				}
				waitForSQLLock(t, pool, false)
				if err := locker.Rollback(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if *result != nil {
				t.Fatal(*result)
			}
			select {
			case code := <-response:
				if !forced && code != 200 {
					t.Fatalf("graceful drain returned %d", code)
				}
			case <-time.After(time.Second):
				t.Fatal("client was left waiting")
			}
			got, err := repo.GetByMD5(context.Background(), hash)
			if err != nil {
				t.Fatal(err)
			}
			want := "replacement"
			if forced {
				want = "initial"
			}
			if got.Name != want {
				t.Fatalf("after shutdown got %q, want %q", got.Name, want)
			}
		})
	}
}

func TestStartupFailuresReturnSafeErrors(t *testing.T) {
	_, cfg, _ := lifecycleDatabase(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	for name, change := range map[string]func(*config.Config){
		"occupied address": func(c *config.Config) { c.HTTPAddr = occupied.Addr().String() },
		"invalid certificate": func(c *config.Config) {
			c.TLSCertFile = "/missing/SECRET_SENTINEL.crt"
			c.TLSKeyFile = "/missing/SECRET_SENTINEL.key"
		},
		"invalid dsn": func(c *config.Config) { c.DatabaseURL = "postgres://user:SECRET_SENTINEL%zz@localhost/db" },
	} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			change(&c)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := run(ctx, c, logger)
			if err == nil || strings.Contains(err.Error(), "SECRET_SENTINEL") {
				t.Fatalf("unsafe startup result: %v", err)
			}
		})
	}
}
