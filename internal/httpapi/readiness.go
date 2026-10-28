package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"threatservice/internal/diagnostic"
)

const readinessTTL = time.Second
const readinessTimeout = time.Second

var errReadinessPanic = errors.New("readiness check panicked")

type readyFlight struct {
	done chan struct{}
	err  error // Published before done is closed; immutable afterwards.
}

// One bounded check is shared by all callers. It is independent of an
// individual HTTP request: canceling a waiter must not cancel other probes.
type readinessCache struct {
	mu      sync.Mutex
	expires time.Time
	err     error
	flight  *readyFlight
}

func (c *readinessCache) check(ctx context.Context, timeout time.Duration, check func(context.Context) error, logger *slog.Logger, requestID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if time.Now().Before(c.expires) {
		err := c.err
		c.mu.Unlock()
		return err
	}
	flight := c.flight
	if flight == nil {
		flight = &readyFlight{done: make(chan struct{})}
		c.flight = flight
		go c.refresh(flight, timeout, check, logger, requestID)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return flight.err
	}
}

func (c *readinessCache) refresh(flight *readyFlight, timeout time.Duration, check func(context.Context) error, logger *slog.Logger, requestID string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	defer func() {
		if recover() != nil {
			err = errReadinessPanic
			logger.Error("readiness check panicked", "request_id", requestID, "operation", "readiness",
				"cause_category", "panic", "stack", diagnostic.PanicStack())
		}
		c.mu.Lock()
		flight.err = err
		c.err, c.expires = err, time.Now().Add(readinessTTL)
		c.flight = nil
		close(flight.done)
		c.mu.Unlock()
	}()
	if check != nil {
		err = check(ctx)
	}
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
}
