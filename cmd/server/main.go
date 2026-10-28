package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/internal/config"
	"threatservice/internal/diagnostic"
	"threatservice/internal/httpapi"
	"threatservice/internal/postgres"
	"threatservice/internal/threat"
	"threatservice/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "operation", "load_configuration", "cause_category", "configuration", "error", err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("service stopped")
		os.Exit(1)
	}
}

func run(stopCtx context.Context, cfg config.Config, logger *slog.Logger) error {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return serverFailure(logger, "parse_database_config", err, "invalid DATABASE_URL")
	}
	poolCfg.MaxConns = cfg.PGMaxConns
	postgres.ConfigurePool(poolCfg)
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "threatservice"
	poolCfg.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(stopCtx, poolCfg)
	if err != nil {
		return serverFailure(logger, "initialize_database_pool", err, "could not initialize database pool")
	}
	startCtx, startCancel := context.WithTimeout(stopCtx, 5*time.Second)
	operation := "connect_database"
	err = pool.Ping(startCtx)
	if err == nil {
		operation = "check_schema"
		err = migrations.Check(startCtx, pool)
	}
	var schema string
	if err == nil {
		operation = "resolve_schema"
		err = pool.QueryRow(startCtx, `SELECT pg_catalog.current_schema()`).Scan(&schema)
	}
	if err != nil && startCtx.Err() != nil {
		err = errors.Join(err, startCtx.Err())
	}
	startCancel()
	if err != nil {
		closePoolBriefly(pool)
		return serverFailure(logger, operation, err, "database unavailable or migrations missing; run the migrate command first")
	}

	var pair tls.Certificate
	if cfg.TLSCertFile != "" {
		pair, err = tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			closePoolBriefly(pool)
			return serverFailure(logger, "load_tls", err, "could not load TLS certificate and private key")
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(stopCtx, "tcp", cfg.HTTPAddr)
	if err != nil {
		closePoolBriefly(pool)
		return serverFailure(logger, "listen_http", err, "could not bind HTTP_ADDR")
	}
	requestsCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	handler := httpapi.New(threat.NewService(postgres.New(pool, cfg.QueryTimeout, schema)), httpapi.Options{
		Logger: logger, RequestTimeout: cfg.RequestTimeout, BearerToken: cfg.APIToken,
		RateLimitRPS: cfg.RateLimitRPS, RateLimitBurst: cfg.RateLimitBurst,
		Ready: func(ctx context.Context) error { return databaseReady(ctx, pool, cfg.QueryTimeout) },
	})
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: cfg.RequestTimeout + 10*time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10,
		BaseContext:    func(net.Listener) context.Context { return requestsCtx },
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}},
		ErrorLog:       log.New(safeTransportLog{logger}, "", 0),
	}
	served := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" {
			served <- server.ServeTLS(listener, "", "")
		} else {
			served <- server.Serve(listener)
		}
	}()
	logger.Info("server started", "address", listener.Addr().String(), "tls", cfg.TLSCertFile != "", "authentication", cfg.APIToken != "", "rate_limit_rps", cfg.RateLimitRPS)
	select {
	case <-stopCtx.Done():
	case err = <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			cancelRequests()
			_ = server.Close()
			closePoolBriefly(pool)
			return serverFailure(logger, "serve_http", err, "HTTP server failed")
		}
	}
	logger.Info("server stopping")
	grace, cancelGrace := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelGrace()
	if err := server.Shutdown(grace); err != nil {
		diagnostic.Log(logger, "", "shutdown_http", err)
		cancelRequests()
		_ = server.Close()
	}
	cancelRequests()
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
		if grace.Err() != nil {
			return serverFailure(logger, "shutdown_pool", grace.Err(), "shutdown deadline exceeded")
		}
		logger.Info("server stopped")
		return nil
	case <-grace.Done():
		return serverFailure(logger, "shutdown_pool", grace.Err(), "shutdown deadline exceeded")
	}
}

func closePoolBriefly(pool *pgxpool.Pool) {
	done := make(chan struct{})
	go func() { pool.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

func serverFailure(logger *slog.Logger, operation string, err error, message string) error {
	diagnostic.Log(logger, "", operation, err)
	return errors.New(message)
}

type safeTransportLog struct{ logger *slog.Logger }

func (w safeTransportLog) Write(p []byte) (int, error) {
	w.logger.Error("HTTP transport error", "operation", "http_transport", "cause_category", "transport")
	return len(p), nil
}

func databaseReady(ctx context.Context, pool *pgxpool.Pool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := pool.Ping(ctx)
	if err == nil {
		err = migrations.Check(ctx, pool)
	}
	if err != nil && ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	return err
}
