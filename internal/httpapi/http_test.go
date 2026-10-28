package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"threatservice/internal/threat"
)

const hash = "0123456789abcdef0123456789abcdef"

type testRepository struct {
	mu    sync.Mutex
	calls int
	md5   string
	input threat.Input
	err   error
}

func (r *testRepository) result(md5 string, value threat.Input) (threat.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.md5, r.input = md5, value
	if r.err != nil {
		return threat.Threat{}, r.err
	}
	now := time.Date(2026, 10, 28, 12, 0, 0, 123456000, time.FixedZone("UTC+3", 3*60*60))
	return threat.Threat{MD5: md5, Name: value.Name, Description: value.Description, Severity: value.Severity, CreatedAt: now, UpdatedAt: now}, nil
}
func (r *testRepository) Create(_ context.Context, md5 string, value threat.Input) (threat.Threat, error) {
	return r.result(md5, value)
}
func (r *testRepository) Replace(_ context.Context, md5 string, value threat.Input) (threat.Threat, error) {
	return r.result(md5, value)
}
func (r *testRepository) GetByMD5(_ context.Context, md5 string) (threat.Threat, error) {
	return r.result(md5, threat.Input{Name: "Stored", Severity: threat.SeverityUnknown})
}
func (r *testRepository) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func testOptions() Options { return Options{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))} }
func testHandler(repo *testRepository) http.Handler {
	return New(threat.NewService(repo), testOptions())
}
func request(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCreateUsesGeneratedResponseAndDefaults(t *testing.T) {
	repo := &testRepository{}
	w := request(testHandler(repo), "POST", "/info", `{"md5":"`+strings.ToUpper(hash)+`","name":"  Троян 🦊  "}`)
	if w.Code != 201 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); got != "/info/"+hash {
		t.Fatalf("Location=%q", got)
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 6 || response["md5"] != hash || response["name"] != "  Троян 🦊  " || response["severity"] != "unknown" || response["description"] != "" {
		t.Fatalf("unexpected response: %v", response)
	}
	if response["created_at"] != "2026-10-28T09:00:00.123456Z" || response["created_at"] != response["updated_at"] {
		t.Fatalf("dates: %v", response)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") == "" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers=%v", w.Header())
	}
}

func TestPUTFullReplacementAndPathNormalization(t *testing.T) {
	repo := &testRepository{}
	w := request(testHandler(repo), "PUT", "/info/"+strings.ToUpper(hash), `{"name":"New"}`)
	if w.Code != 200 {
		t.Fatalf("status=%d: %s", w.Code, w.Body)
	}
	if repo.md5 != hash || repo.input.Description != "" || repo.input.Severity != threat.SeverityUnknown || repo.input.Name != "New" {
		t.Fatalf("input=%+v md5=%s", repo.input, repo.md5)
	}
	w = request(testHandler(repo), "GET", "/info/"+hash+"?ignored=yes", "")
	if w.Code != 200 {
		t.Fatalf("GET status=%d", w.Code)
	}
}

func TestStrictJSONAndFieldValidation(t *testing.T) {
	valid := `{"md5":"` + hash + `","name":"ok"}`
	cases := map[string]string{
		"empty": "", "null": "null", "array": "[]", "two objects": valid + valid,
		"missing name": `{"md5":"` + hash + `"}`, "missing hash": `{"name":"x"}`,
		"null name": `{"md5":"` + hash + `","name":null}`, "null optional": `{"md5":"` + hash + `","name":"x","severity":null}`,
		"wrong type": `{"md5":"` + hash + `","name":1}`, "unknown field": `{"md5":"` + hash + `","name":"x","extra":"x"}`,
		"case": `{"md5":"` + hash + `","Name":"x"}`, "duplicate": `{"md5":"` + hash + `","name":"x","name":"y"}`,
		"escaped duplicate": `{"md5":"` + hash + `","name":"x","\u006eame":"y"}`,
		"high surrogate":    `{"md5":"` + hash + `","name":"\uD800"}`, "low surrogate": `{"md5":"` + hash + `","name":"\uDC00"}`,
		"invalid UTF8":     `{"md5":"` + hash + `","name":"` + string([]byte{0xff}) + `"}`,
		"NUL":              `{"md5":"` + hash + `","name":"\u0000"}`,
		"blank":            `{"md5":"` + hash + `","name":"\t\u2003"}`,
		"long name":        `{"md5":"` + hash + `","name":"` + strings.Repeat("я", 256) + `"}`,
		"long description": `{"md5":"` + hash + `","name":"x","description":"` + strings.Repeat("я", 4001) + `"}`,
		"empty severity":   `{"md5":"` + hash + `","name":"x","severity":""}`,
		"unknown severity": `{"md5":"` + hash + `","name":"x","severity":"safe"}`,
		"bad hash":         `{"md5":"` + hash + ` ","name":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &testRepository{}
			w := request(testHandler(repo), "POST", "/info", body)
			if w.Code != 400 || repo.count() != 0 {
				t.Fatalf("status=%d storage calls=%d: %s", w.Code, repo.count(), w.Body)
			}
		})
	}
	for _, name := range []string{strings.Repeat("я", 255), `\uD83E\uDD8A`, `\\uD800`, `�`} {
		w := request(testHandler(&testRepository{}), "POST", "/info", `{"md5":"`+hash+`","name":"`+name+`","description":"`+strings.Repeat("я", 4000)+`"}`)
		if w.Code != 201 {
			t.Fatalf("valid Unicode %q rejected: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestMediaTypeBodyLimitAndPriority(t *testing.T) {
	valid := `{"md5":"` + hash + `","name":"x"}`
	for _, contentType := range []string{"", "text/plain", "application/json; charset=iso-8859-1", "application/json; extra=yes", "application/json, application/json"} {
		r := httptest.NewRequest("POST", "/info", strings.NewReader(valid))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		testHandler(&testRepository{}).ServeHTTP(w, r)
		if w.Code != 415 {
			t.Fatalf("%q: status=%d", contentType, w.Code)
		}
	}
	for _, size := range []int{65536, 65537} {
		body := valid + strings.Repeat(" ", size-len(valid))
		r := httptest.NewRequest("POST", "/info", strings.NewReader(body))
		r.ContentLength = -1
		r.Header.Set("Content-Type", "Application/JSON; charset=UTF-8")
		w := httptest.NewRecorder()
		testHandler(&testRepository{}).ServeHTTP(w, r)
		expected := 201
		if size > 65536 {
			expected = 413
		}
		if w.Code != expected {
			t.Fatalf("size=%d status=%d body=%s", size, w.Code, w.Body)
		}
	}
	r := httptest.NewRequest("POST", "/info", strings.NewReader("x"+strings.Repeat(" ", 65536)))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testHandler(&testRepository{}).ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("oversize must precede JSON: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/info", strings.NewReader(valid))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Encoding", "gzip")
	w = httptest.NewRecorder()
	testHandler(&testRepository{}).ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatalf("encoding: %d", w.Code)
	}
	w = request(testHandler(&testRepository{}), "PUT", "/info/bad", "not JSON")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "md5") {
		t.Fatalf("path validation must precede body: %s", w.Body)
	}
}

func TestRepositoryErrorsAreMappedWithoutLeaks(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{{threat.ErrNotFound, 404}, {threat.ErrAlreadyExists, 409}, {errors.New("secret DSN postgres://password@private"), 500}, {context.DeadlineExceeded, 500}} {
		w := request(testHandler(&testRepository{err: tc.err}), "GET", "/info/"+hash, "")
		if w.Code != tc.status {
			t.Fatalf("%v: %d", tc.err, w.Code)
		}
		if w.Code == 500 && (strings.Contains(w.Body.String(), "details") || strings.Contains(w.Body.String(), "secret")) {
			t.Fatalf("leaked internal error: %s", w.Body)
		}
	}
}

func TestRoutingAndHEADUseRealHTTP(t *testing.T) {
	server := httptest.NewServer(testHandler(&testRepository{}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, tc := range []struct {
		method, path string
		status       int
		allow        string
	}{
		{"HEAD", "/info/" + hash, 405, "GET, PUT"}, {"GET", "/info", 405, "POST"}, {"OPTIONS", "/info", 405, "POST"},
		{"GET", "/info/", 404, ""}, {"GET", "/info//" + hash, 404, ""}, {"GET", "/info/../info", 404, ""},
		{"GET", "/info/" + hash + "/extra", 404, ""}, {"GET", "/unknown", 404, ""},
		{"GET", "/info/bad", 400, ""}, {"GET", "/info/%2F", 400, ""},
		{"GET", "/info/%30" + hash[1:], 200, ""}, {"HEAD", "/unknown", 404, ""},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || response.Header.Get("Allow") != tc.allow || response.Header.Get("Location") != "" {
				t.Fatalf("status=%d allow=%q headers=%v body=%s", response.StatusCode, response.Header.Get("Allow"), response.Header, body)
			}
			if tc.method == "HEAD" && len(body) != 0 {
				t.Fatalf("HEAD body=%q", body)
			}
		})
	}
}

func TestRealHTTPBodyReadIsBoundedByRequestDeadline(t *testing.T) {
	repo := &testRepository{}
	options := testOptions()
	options.RequestTimeout = 80 * time.Millisecond
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
	started := time.Now()
	// Leave the declared body incomplete while keeping the connection open.
	_, err = io.WriteString(connection, "POST /info HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"name\":")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
	if err == nil {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != 400 && response.StatusCode != 500 {
			t.Fatalf("status=%d", response.StatusCode)
		}
	}
	// Transport errors are permitted, but a slow sender must release the
	// handler and must never reach the repository with a partial body.
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("slow body exceeded budget: %v, error=%v", elapsed, err)
	}
	if repo.count() != 0 {
		t.Fatal("partial request reached storage")
	}
}

func TestOptionalAuthenticationRateLimitAndHealth(t *testing.T) {
	var notReady atomic.Bool
	options := testOptions()
	options.BearerToken = "test-secret"
	options.RateLimitRPS = 0.001
	options.RateLimitBurst = 1
	options.Ready = func(context.Context) error {
		if notReady.Load() {
			return errors.New("private DSN")
		}
		return nil
	}
	h := New(threat.NewService(&testRepository{}), options)
	for _, token := range []string{"", "Bearer bad", "Basic test-secret"} {
		r := httptest.NewRequest("GET", "/info/"+hash, nil)
		r.Header.Set("Authorization", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("auth=%q: %d", token, w.Code)
		}
	}
	for i, expected := range []int{200, 429} {
		r := httptest.NewRequest("GET", "/info/"+hash, nil)
		r.Header.Set("Authorization", "Bearer test-secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatalf("request=%d status=%d", i, w.Code)
		}
		if expected == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("missing Retry-After")
		}
	}
	for _, path := range []string{"/health/live", "/health/ready"} {
		w := request(h, "GET", path, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	notReady.Store(true)
	// Expire the cache explicitly here; real TTL behavior is tested separately.
	cache := &h.(*handler).readiness
	cache.mu.Lock()
	cache.expires = time.Time{}
	cache.mu.Unlock()
	w := request(h, "GET", "/health/ready", "")
	if w.Code != 503 || strings.Contains(w.Body.String(), "DSN") {
		t.Fatalf("ready: %d %s", w.Code, w.Body)
	}
}

func TestReadinessCacheIsIndependentOfBusinessLimiter(t *testing.T) {
	var readyCalls atomic.Int64
	options := testOptions()
	options.RateLimitRPS = 0.001
	options.RateLimitBurst = 1
	options.Ready = func(context.Context) error { readyCalls.Add(1); return nil }
	h := New(threat.NewService(&testRepository{}), options)
	for i := 0; i < 20; i++ {
		w := request(h, "GET", "/health/ready", "")
		if w.Code != 200 || w.Header().Get("Retry-After") != "" {
			t.Fatalf("readiness request %d: status=%d headers=%v", i, w.Code, w.Header())
		}
	}
	if readyCalls.Load() != 1 {
		t.Fatalf("Ready invoked %d times; expected one cached check", readyCalls.Load())
	}
	if w := request(h, "GET", "/info/"+hash, ""); w.Code != 200 {
		t.Fatalf("readiness consumed business quota: %d", w.Code)
	}
	if w := request(h, "GET", "/info/"+hash, ""); w.Code != 429 {
		t.Fatalf("business limit not enforced: %d", w.Code)
	}
	for i := 0; i < 4; i++ {
		if w := request(h, "GET", "/health/live", ""); w.Code != 200 {
			t.Fatalf("liveness was limited: %d", w.Code)
		}
	}
	// Even an exhausted business quota must not prevent a fresh DB check.
	h = New(threat.NewService(&testRepository{}), options)
	request(h, "GET", "/info/"+hash, "")
	request(h, "GET", "/info/"+hash, "")
	if w := request(h, "GET", "/health/ready", ""); w.Code != 200 {
		t.Fatalf("business quota limited readiness: %d", w.Code)
	}
}

type panicService struct{}

func (panicService) Create(context.Context, string, threat.Input) (threat.Threat, error) {
	panic("private panic")
}
func (panicService) GetByMD5(context.Context, string) (threat.Threat, error) { panic("private panic") }
func (panicService) Replace(context.Context, string, threat.Input) (threat.Threat, error) {
	panic("private panic")
}

func TestRecoveryAndLogsAreSafe(t *testing.T) {
	var logs bytes.Buffer
	options := testOptions()
	options.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	w := request(New(panicService{}, options), "GET", "/info/"+hash, "")
	if w.Code != 500 || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("response=%d %s", w.Code, w.Body)
	}
	entries := logEvents(t, &logs)
	if len(entries) != 2 {
		t.Fatalf("events=%v", entries)
	}
	failure, entry := entries[0], entries[1]
	stack, _ := failure["stack"].(string)
	if failure["level"] != "ERROR" || failure["cause_category"] != "panic" || failure["operation"] != "get_threat" || failure["request_id"] != w.Header().Get("X-Request-ID") || !strings.Contains(stack, "panicService.GetByMD5") || !strings.Contains(stack, "http_test.go:") {
		t.Fatalf("missing panic diagnostic: %v", failure)
	}
	if entry["request_id"] != w.Header().Get("X-Request-ID") || entry["error_class"] != "panic" || entry["route"] != "/info/{md5}" || strings.Contains(logs.String(), hash) || strings.Contains(logs.String(), "private") {
		t.Fatalf("unsafe log: %s", logs.String())
	}
}
