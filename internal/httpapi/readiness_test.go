package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentReadinessProbesShareOneCheck(t *testing.T) {
	var calls, active, maximum atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	options := testOptions()
	options.Ready = func(ctx context.Context) error {
		calls.Add(1)
		n := active.Add(1)
		maximum.Store(max(maximum.Load(), n))
		defer active.Add(-1)
		if n == 1 {
			close(entered)
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	h := New(nil, options)
	const count = 40
	results := make(chan int, count)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func() { defer wait.Done(); <-start; results <- request(h, "GET", "/health/ready", "").Code }()
	}
	close(start)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("check did not start")
	}
	if w := request(h, "GET", "/health/live", ""); w.Code != 200 {
		t.Fatalf("liveness blocked: %d", w.Code)
	}
	close(release)
	wait.Wait()
	close(results)
	for code := range results {
		if code != 200 {
			t.Fatalf("readiness=%d", code)
		}
	}
	if calls.Load() != 1 || maximum.Load() != 1 || active.Load() != 0 {
		t.Fatalf("calls=%d max=%d active=%d", calls.Load(), maximum.Load(), active.Load())
	}
}

func TestReadinessExpiresSuccessAndFailureThenRecovers(t *testing.T) {
	var down atomic.Bool
	var calls atomic.Int64
	options := testOptions()
	options.Ready = func(context.Context) error {
		calls.Add(1)
		if down.Load() {
			return errors.New("private database failure")
		}
		return nil
	}
	h := New(nil, options)
	probe := func(status int, count int64) {
		t.Helper()
		w := request(h, "GET", "/health/ready", "")
		if w.Code != status || calls.Load() != count {
			t.Fatalf("status=%d calls=%d, want %d/%d", w.Code, calls.Load(), status, count)
		}
	}
	probe(200, 1)
	down.Store(true)
	probe(200, 1) // A successful result is allowed only within the TTL.
	time.Sleep(readinessTTL + 20*time.Millisecond)
	probe(503, 2)
	probe(503, 2)
	down.Store(false)
	probe(503, 2) // Failures are cached too, preventing an outage stampede.
	time.Sleep(readinessTTL + 20*time.Millisecond)
	probe(200, 3)
}

func TestCanceledReadinessWaitersDoNotCancelSharedCheck(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int64
			options := testOptions()
			options.Ready = func(ctx context.Context) error {
				calls.Add(1)
				close(entered)
				defer close(finished)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			h := New(nil, options)
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			result := make(chan int, 1)
			go func() {
				r := httptest.NewRequest("GET", "/health/ready", nil).WithContext(ctx)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				result <- w.Code
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("check did not start")
			}
			if !deadline {
				cancel()
			}
			select {
			case code := <-result:
				if code != 503 {
					t.Fatalf("canceled waiter=%d", code)
				}
			case <-time.After(time.Second):
				t.Fatal("waiter ignored cancellation")
			}
			select {
			case <-finished:
				t.Fatal("waiter canceled the shared DB check")
			default:
			}
			close(release)
			if w := request(h, "GET", "/health/ready", ""); w.Code != 200 {
				t.Fatalf("another waiter failed: %d", w.Code)
			}
			if calls.Load() != 1 {
				t.Fatalf("duplicate checks=%d", calls.Load())
			}
		})
	}
}

func TestReadinessCheckHasItsOwnDeadline(t *testing.T) {
	options := testOptions()
	options.RequestTimeout = 40 * time.Millisecond
	exited := make(chan struct{})
	var calls atomic.Int64
	options.Ready = func(ctx context.Context) error {
		if calls.Add(1) > 1 {
			return nil
		}
		defer close(exited)
		<-ctx.Done()
		return ctx.Err()
	}
	h := New(nil, options).(*handler)
	if w := request(h, "GET", "/health/ready", ""); w.Code != 503 {
		t.Fatalf("deadline=%d", w.Code)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("check has no deadline")
	}
	h.readiness.mu.Lock()
	flight := h.readiness.flight
	h.readiness.mu.Unlock()
	if flight != nil {
		select {
		case <-flight.done:
		case <-time.After(time.Second):
			t.Fatal("check did not finish")
		}
	}
	// A completed timeout cannot leave an in-flight marker blocking recovery.
	h.readiness.mu.Lock()
	h.readiness.expires = time.Time{}
	h.readiness.mu.Unlock()
	if w := request(h, "GET", "/health/ready", ""); w.Code != 200 {
		t.Fatalf("recovery=%d", w.Code)
	}
}

func TestReadinessPanicPublishesFailureAndStack(t *testing.T) {
	var logs bytes.Buffer
	var calls atomic.Int64
	options := testOptions()
	options.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	options.Ready = func(context.Context) error {
		if calls.Add(1) == 1 {
			panic("SECRET")
		}
		return nil
	}
	h := New(nil, options).(*handler)
	w := request(h, http.MethodGet, "/health/ready", "")
	if w.Code != 503 || strings.Contains(logs.String(), "SECRET") || strings.Contains(w.Body.String(), "SECRET") {
		t.Fatalf("unsafe panic: %d %s", w.Code, logs.String())
	}
	entry := logEvents(t, &logs)[0]
	stack, _ := entry["stack"].(string)
	if entry["cause_category"] != "panic" || entry["request_id"] != w.Header().Get("X-Request-ID") || !strings.Contains(stack, "readiness_test.go:") {
		t.Fatalf("missing stack: %v", entry)
	}
	h.readiness.mu.Lock()
	h.readiness.expires = time.Time{}
	h.readiness.mu.Unlock()
	if w := request(h, "GET", "/health/ready", ""); w.Code != 200 {
		t.Fatalf("panic left readiness stuck: %d", w.Code)
	}
}
