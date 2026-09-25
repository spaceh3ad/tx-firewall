package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spaceh3ad/tx-firewall/internal/logging"
	"github.com/spaceh3ad/tx-firewall/internal/proxy"
)

func main() {
	logger, err := logging.New(os.Stderr, getEnv("LOG_FORMAT", "pretty"), getEnv("LOG_LEVEL", "info"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err) // logger isn't available yet
		os.Exit(1)
	}
	slog.SetDefault(logger)
	log := logger.With("component", "main")

	upstreamURL := mustGetEnv("UPSTREAM_URL")
	listenAddr := mustGetEnv("LISTEN_ADDR")

	upstream, err := url.Parse(upstreamURL)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		log.Error("UPSTREAM_URL must be a full URL like http://host:port", "url", upstreamURL)
		os.Exit(1)
	}

	// explicit timeouts protect against slowloris
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           proxy.NewHandler(upstream, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	log.Info("proxy listening", "addr", listenAddr, "upstream", upstreamURL)
	if err := server.ListenAndServe(); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustGetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required environment variable", "key", key)
		os.Exit(1)
	}
	return v
}
