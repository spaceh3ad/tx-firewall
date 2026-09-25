package main

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spaceh3ad/tx-firewall/internal/proxy"
)

func main() {
	upstreamURL := mustGetEnv("UPSTREAM_URL")
	listenAddr := mustGetEnv("LISTEN_ADDR")

	upstream, err := url.Parse(upstreamURL)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		slog.Error("UPSTREAM_URL must be a full URL like http://host:port", "url", upstreamURL)
		os.Exit(1)
	}

	// explicit timeouts protect against slowloris
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           proxy.NewHandler(upstream),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	slog.Info("proxy listening", "addr", listenAddr, "upstream", upstreamURL)
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func mustGetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required environment variable", "key", key)
		os.Exit(1)
	}
	return v
}
