package httpapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"threatservice/internal/threat"
)

func TestLargeRejectedInputsDoNotAmplifyAllocations(t *testing.T) {
	options := testOptions()
	options.BearerToken = "0123456789abcdef"
	h := New(threat.NewService(&testRepository{}), options).(*handler)
	r := httptest.NewRequest("GET", "/info/"+hash, nil)
	r.Header.Set("Authorization", strings.Repeat("x ", 32000))
	measurement := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if h.authorized(r) {
				b.Fatal("invalid authorization was accepted")
			}
		}
	})
	if allocated := measurement.AllocedBytesPerOp(); allocated > 1024 {
		t.Fatalf("authorization rejection allocated %d bytes for a 64 KiB header", allocated)
	}

	r = httptest.NewRequest("GET", "/info/"+strings.Repeat("/", 60000), nil)
	measurement = testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 404 {
				b.Fatalf("status=%d", w.Code)
			}
		}
	})
	if allocated := measurement.AllocedBytesPerOp(); allocated > 16*1024 {
		t.Fatalf("unknown-route rejection allocated %d bytes for a 60 KiB URI", allocated)
	}
}

func TestRawChunkedBodiesAndFramingErrors(t *testing.T) {
	valid := `{"md5":"` + hash + `","name":"Raw.Chunked"}`
	chunk := func(value string) string { return fmt.Sprintf("%x\r\n%s\r\n", len(value), value) }
	for _, tc := range []struct {
		name, headers, body string
		status, calls       int
	}{
		{"valid chunked", "Transfer-Encoding: chunked\r\n", chunk(valid[:13]) + chunk(valid[13:]) + "0\r\n\r\n", 201, 1},
		{"allowed trailer", "Transfer-Encoding: chunked\r\nTrailer: X-Trace\r\n", chunk(valid) + "0\r\nX-Trace: safe\r\n\r\n", 201, 1},
		{"too large chunked", "Transfer-Encoding: chunked\r\n", chunk("x"+strings.Repeat(" ", 65536)) + "0\r\n\r\n", 413, 0},
		{"bad next chunk", "Transfer-Encoding: chunked\r\n", chunk(valid) + "z\r\n", 400, 0},
		{"bad chunk delimiter", "Transfer-Encoding: chunked\r\n", fmt.Sprintf("%x\r\n%sXX0\r\n\r\n", len(valid), valid), 400, 0},
		{"forbidden trailer framing", "Transfer-Encoding: chunked\r\nTrailer: Content-Length\r\n", chunk(valid) + "0\r\nContent-Length: 0\r\n\r\n", 400, 0},
		{"conflicting lengths", "Content-Length: 0\r\nContent-Length: 20\r\n", valid, 400, 0},
		{"negative length", "Content-Length: -1\r\n", valid, 400, 0},
		{"no body length", "", valid, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &testRepository{}
			options := testOptions()
			options.RequestTimeout = 300 * time.Millisecond
			server := httptest.NewServer(New(threat.NewService(repo), options))
			defer server.Close()
			connection, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := "POST /info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n" + tc.headers + "\r\n" + tc.body
			if _, err := io.WriteString(connection, payload); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || repo.count() != tc.calls {
				t.Fatalf("status=%d calls=%d body=%s", response.StatusCode, repo.count(), body)
			}
		})
	}
}

type cancellationService struct {
	entered   chan struct{}
	cancelled chan struct{}
}

func (s cancellationService) Create(ctx context.Context, _ string, _ threat.Input) (threat.Threat, error) {
	return s.GetByMD5(ctx, "")
}
func (s cancellationService) Replace(ctx context.Context, _ string, _ threat.Input) (threat.Threat, error) {
	return s.GetByMD5(ctx, "")
}
func (s cancellationService) GetByMD5(ctx context.Context, _ string) (threat.Threat, error) {
	close(s.entered)
	<-ctx.Done()
	close(s.cancelled)
	return threat.Threat{}, ctx.Err()
}

func TestRealClientDisconnectCancelsService(t *testing.T) {
	s := cancellationService{entered: make(chan struct{}), cancelled: make(chan struct{})}
	options := testOptions()
	options.RequestTimeout = 5 * time.Second
	server := httptest.NewServer(New(s, options))
	defer server.Close()
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "GET /info/"+hash+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("service was not entered")
	}
	connection.Close()
	select {
	case <-s.cancelled:
	case <-time.After(time.Second):
		t.Fatal("client disconnect did not cancel the service")
	}
}

func TestRejectedExpectContinueDoesNotReadBody(t *testing.T) {
	for _, tc := range []struct {
		name, headers string
		options       Options
		status        int
	}{
		{"large body", "Content-Length: 65537\r\nContent-Type: application/json\r\n", testOptions(), 413},
		{"wrong media type", "Content-Length: 200\r\nContent-Type: text/plain\r\n", testOptions(), 415},
		{"missing bearer", "Content-Length: 200\r\nContent-Type: application/json\r\n", func() Options { v := testOptions(); v.BearerToken = "0123456789abcdef"; return v }(), 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &testRepository{}
			server := httptest.NewServer(New(threat.NewService(repo), tc.options))
			defer server.Close()
			connection, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(connection, "POST /info HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n"+tc.headers+"\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.status || repo.count() != 0 {
				t.Fatalf("status=%d calls=%d", response.StatusCode, repo.count())
			}
		})
	}
}
