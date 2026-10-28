package httpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"

	"threatservice/internal/threat"
)

func contractRouter(t *testing.T) routers.Router {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	router, err := legacy.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func contractInput(t *testing.T, router routers.Router, method, path, body string) *openapi3filter.RequestValidationInput {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost:8080"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	route, params, err := router.FindRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	return &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route,
		// This handler uses the documented unauthenticated profile; access-control
		// behavior is exercised separately by the authentication tests.
		Options: &openapi3filter.Options{SkipSettingDefaults: true, AuthenticationFunc: openapi3filter.NoopAuthenticationFunc}}
}

func validateContractResponse(input *openapi3filter.RequestValidationInput, expected int, response *http.Response) error {
	if response.StatusCode != expected {
		return fmt.Errorf("status %d, expected %d", response.StatusCode, expected)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("expected application/json")
	}
	definition := input.Route.Operation.Responses.Status(expected)
	if definition == nil {
		return fmt.Errorf("status %d is not explicitly specified", expected)
	}
	// OpenAPI response headers are optional unless marked required. Our API
	// promises these headers on every corresponding response, so require them.
	for name := range definition.Value.Headers {
		if response.Header.Get(name) == "" {
			return fmt.Errorf("missing response header %s", name)
		}
	}
	return openapi3filter.ValidateResponse(context.Background(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: input, Status: response.StatusCode, Header: response.Header, Body: response.Body,
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	})
}

func TestHTTPContractAgainstOpenAPI(t *testing.T) {
	router := contractRouter(t)
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		invalidRequest           bool
		storageError             error
	}{
		{"create minimal", "POST", "/info", `{"md5":"` + strings.ToUpper(hash) + `","name":"Trojan"}`, 201, false, nil},
		{"create full", "POST", "/info", `{"md5":"` + hash + `","name":"Троян 🦊","description":"Details","severity":"critical"}`, 201, false, nil},
		{"conflict", "POST", "/info", `{"md5":"` + hash + `","name":"Trojan"}`, 409, false, threat.ErrAlreadyExists},
		{"get", "GET", "/info/" + strings.ToUpper(hash), "", 200, false, nil},
		{"missing get", "GET", "/info/" + hash, "", 404, false, threat.ErrNotFound},
		{"replace minimal", "PUT", "/info/" + hash, `{"name":"Replacement"}`, 200, false, nil},
		{"replace full", "PUT", "/info/" + hash, `{"name":"Replacement","description":"Updated","severity":"low"}`, 200, false, nil},
		{"missing put", "PUT", "/info/" + hash, `{"name":"Replacement"}`, 404, false, threat.ErrNotFound},
		{"invalid hash body", "POST", "/info", `{"md5":"invalid","name":"Trojan"}`, 400, true, nil},
		{"missing name", "POST", "/info", `{"md5":"` + hash + `"}`, 400, true, nil},
		{"invalid path", "GET", "/info/invalid", "", 400, true, nil},
		{"invalid put", "PUT", "/info/" + hash, `{"name":null}`, 400, true, nil},
		{"extra field", "PUT", "/info/" + hash, `{"name":"x","extra":1}`, 400, true, nil},
		{"invalid severity", "PUT", "/info/" + hash, `{"name":"x","severity":"safe"}`, 400, true, nil},
		{"duplicate key", "POST", "/info", `{"md5":"` + hash + `","name":"x","\u006eame":"y"}`, 400, true, nil},
		{"malformed JSON", "POST", "/info", `{"md5":`, 400, true, nil},
		{"two objects", "PUT", "/info/" + hash, `{"name":"x"}{"name":"y"}`, 400, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := contractInput(t, router, tc.method, tc.path, tc.body)
			if !tc.invalidRequest {
				if err := openapi3filter.ValidateRequest(context.Background(), input); err != nil {
					t.Fatalf("valid request does not match OpenAPI: %v", err)
				}
			}
			// Use a fresh request: validation must not supply defaults or otherwise
			// repair the bytes passed to the real handler.
			repo := &testRepository{err: tc.storageError}
			w := request(testHandler(repo), tc.method, tc.path, tc.body)
			if tc.invalidRequest && repo.count() != 0 {
				t.Fatal("invalid input reached storage")
			}
			if err := validateContractResponse(input, tc.status, w.Result()); err != nil {
				t.Fatal(err)
			}
			if tc.status == 201 && w.Header().Get("Location") != "/info/"+hash {
				t.Fatalf("Location=%s", w.Header().Get("Location"))
			}
		})
	}
}

func TestContractValidatorDetectsResponseRegressions(t *testing.T) {
	router := contractRouter(t)
	input := contractInput(t, router, "POST", "/info", `{"md5":"`+hash+`","name":"x"}`)
	for name, mutate := range map[string]func(*http.Response){
		"status":            func(w *http.Response) { w.StatusCode = 200 },
		"content type":      func(w *http.Response) { w.Header.Set("Content-Type", "text/plain") },
		"location":          func(w *http.Response) { w.Header.Del("Location") },
		"cache control":     func(w *http.Response) { w.Header.Del("Cache-Control") },
		"request id":        func(w *http.Response) { w.Header.Del("X-Request-ID") },
		"required property": func(w *http.Response) { w.Body = io.NopCloser(strings.NewReader(`{"md5":"` + hash + `"}`)) },
		"invalid JSON":      func(w *http.Response) { w.Body = io.NopCloser(strings.NewReader(`not JSON`)) },
	} {
		t.Run(name, func(t *testing.T) {
			w := request(testHandler(&testRepository{}), "POST", "/info", `{"md5":"`+hash+`","name":"x"}`)
			response := w.Result()
			mutate(response)
			if err := validateContractResponse(input, 201, response); err == nil {
				t.Fatal("contract regression went undetected")
			}
		})
	}
}
