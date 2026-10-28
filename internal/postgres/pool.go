package postgres

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConfigurePool asks a reachable server to acknowledge query cancellation before
// falling back to a connection deadline. A failed connection can still leave the
// outcome of a write unknown; callers must never retry writes automatically.
// Call this before pgxpool.NewWithConfig, for application and test pools alike.
func ConfigurePool(config *pgxpool.Config) {
	config.ConnConfig.BuildContextWatcherHandler = func(conn *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{
			Conn:               conn,
			CancelRequestDelay: 0,
			DeadlineDelay:      250 * time.Millisecond,
		}
	}
	previous := config.AfterConnect
	var mu sync.Mutex
	targets := make(map[string]string)
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		if previous != nil {
			if err := previous(ctx, connection); err != nil {
				return err
			}
		}
		var user string
		var schema *string
		if err := connection.QueryRow(ctx, `SELECT current_user, pg_catalog.current_schema()`).Scan(&user, &schema); err != nil {
			return fmt.Errorf("resolve application schema: %w", err)
		}
		// Config copies may intentionally choose another search_path. Within one
		// configuration, reconnecting must never switch to a fallback schema.
		key := connection.Config().Database + "\x00" + user + "\x00" + connection.Config().RuntimeParams["search_path"]
		mu.Lock()
		target, exists := targets[key]
		if !exists && schema != nil {
			target = *schema
			targets[key] = target
		}
		mu.Unlock()
		if target == "" {
			return fmt.Errorf("no accessible application schema")
		}
		path := pgx.Identifier{target}.Sanitize() + ", pg_temp"
		if _, err := connection.Exec(ctx, `SELECT pg_catalog.set_config('search_path', $1, false)`, path); err != nil {
			return fmt.Errorf("pin application schema: %w", err)
		}
		return nil
	}
}
