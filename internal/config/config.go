package config

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr        string
	DatabaseURL     string
	PGMaxConns      int32
	RequestTimeout  time.Duration
	QueryTimeout    time.Duration
	ShutdownTimeout time.Duration
	APIToken        string
	RateLimitRPS    float64
	RateLimitBurst  int
	TLSCertFile     string
	TLSKeyFile      string
}

func Load() (Config, error) {
	get := os.Getenv
	c := Config{HTTPAddr: ":8080", DatabaseURL: get("DATABASE_URL"), PGMaxConns: 10,
		RequestTimeout: 3 * time.Second, QueryTimeout: 2 * time.Second, ShutdownTimeout: 10 * time.Second,
		APIToken: get("API_TOKEN"), RateLimitBurst: 20, TLSCertFile: get("TLS_CERT_FILE"), TLSKeyFile: get("TLS_KEY_FILE")}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	if v := get("HTTP_ADDR"); v != "" {
		c.HTTPAddr = v
	}
	_, port, err := net.SplitHostPort(c.HTTPAddr)
	if err != nil {
		return c, fmt.Errorf("HTTP_ADDR must be a host:port address")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return c, fmt.Errorf("HTTP_ADDR must contain a port from 1 to 65535")
	}
	if v := get("PG_MAX_CONNS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 {
			return c, fmt.Errorf("PG_MAX_CONNS must be a positive integer")
		}
		c.PGMaxConns = int32(n)
	}
	for name, dst := range map[string]*time.Duration{"REQUEST_TIMEOUT": &c.RequestTimeout, "QUERY_TIMEOUT": &c.QueryTimeout, "SHUTDOWN_TIMEOUT": &c.ShutdownTimeout} {
		if v := get(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return c, fmt.Errorf("%s must be a positive Go duration", name)
			}
			*dst = d
		}
	}
	if c.QueryTimeout > c.RequestTimeout {
		return c, fmt.Errorf("QUERY_TIMEOUT must not exceed REQUEST_TIMEOUT")
	}
	if c.RequestTimeout > time.Duration(math.MaxInt64)-10*time.Second {
		return c, fmt.Errorf("REQUEST_TIMEOUT is too large for the HTTP write deadline")
	}
	if v := get("RATE_LIMIT_RPS"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return c, fmt.Errorf("RATE_LIMIT_RPS must be a finite nonnegative number")
		}
		c.RateLimitRPS = n
	}
	if v := get("RATE_LIMIT_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("RATE_LIMIT_BURST must be a positive integer")
		}
		c.RateLimitBurst = n
	}
	if c.APIToken != "" && !validBearerToken(c.APIToken) {
		return c, fmt.Errorf("API_TOKEN must contain 16 to 1024 ASCII token68 characters")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return c, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	return c, nil
}

func validBearerToken(value string) bool {
	if len(value) < 16 || len(value) > 1024 || value[0] == '=' {
		return false
	}
	padding := false
	for _, c := range []byte(value) {
		if c == '=' {
			padding = true
			continue
		}
		if padding {
			return false
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}
