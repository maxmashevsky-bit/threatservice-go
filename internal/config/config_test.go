package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	c, err := load(func(k string) string {
		if k == "DATABASE_URL" {
			return "postgres://owner@localhost/threats"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" || c.PGMaxConns != 10 || c.RequestTimeout != 3*time.Second || c.QueryTimeout != 2*time.Second || c.ShutdownTimeout != 10*time.Second || c.RateLimitRPS != 0 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestInvalidConfigurationDoesNotRevealValues(t *testing.T) {
	for _, tt := range []struct{ name, key, value string }{
		{"missing dsn", "DATABASE_URL", ""}, {"bad address", "HTTP_ADDR", "secret-invalid-address"},
		{"zero port", "HTTP_ADDR", ":0"}, {"huge port", "HTTP_ADDR", ":99999"},
		{"negative pool", "PG_MAX_CONNS", "-1"}, {"duration", "REQUEST_TIMEOUT", "secret-invalid-time"},
		{"zero timeout", "QUERY_TIMEOUT", "0s"}, {"long query", "QUERY_TIMEOUT", "5s"},
		{"negative rate", "RATE_LIMIT_RPS", "-1"}, {"nan rate", "RATE_LIMIT_RPS", "NaN"},
		{"infinite rate", "RATE_LIMIT_RPS", "+Inf"}, {"burst", "RATE_LIMIT_BURST", "0"},
		{"short token", "API_TOKEN", "secret-token"}, {"whitespace token", "API_TOKEN", "a-long-secret token"},
		{"unicode whitespace token", "API_TOKEN", "a-long-secret\u2003token"},
		{"control token", "API_TOKEN", "a-long-secret\x01token"},
		{"bad padding", "API_TOKEN", "a-long-secret=token"},
		{"only padding", "API_TOKEN", "================"},
		{"unusable oversized token", "API_TOKEN", strings.Repeat("a", 1025)},
		{"write timeout overflow", "REQUEST_TIMEOUT", "2562047h47m16.854775807s"},
		{"missing key", "TLS_CERT_FILE", "secret-cert-file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"DATABASE_URL": "postgres://owner:password@localhost/threats"}
			env[tt.key] = tt.value
			_, err := load(func(k string) string { return env[k] })
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), "password") {
				t.Fatalf("value leaked: %v", err)
			}
		})
	}
}

func TestCustomConfiguration(t *testing.T) {
	env := map[string]string{"DATABASE_URL": "postgres://owner@localhost/threats", "HTTP_ADDR": "127.0.0.1:9090", "PG_MAX_CONNS": "3", "REQUEST_TIMEOUT": "500ms", "QUERY_TIMEOUT": "100ms", "SHUTDOWN_TIMEOUT": "5s", "API_TOKEN": "1234567890123456", "RATE_LIMIT_RPS": "2.5", "RATE_LIMIT_BURST": "4", "TLS_CERT_FILE": "cert.pem", "TLS_KEY_FILE": "key.pem"}
	c, err := load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimitRPS != 2.5 || c.RateLimitBurst != 4 || c.PGMaxConns != 3 || c.QueryTimeout != 100*time.Millisecond || c.APIToken != "1234567890123456" {
		t.Fatalf("unexpected config: %+v", c)
	}
}
