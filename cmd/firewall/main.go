package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spaceh3ad/tx-firewall/internal/logging"
	"github.com/spaceh3ad/tx-firewall/internal/proxy"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/sanctions"
	"github.com/spaceh3ad/tx-firewall/internal/screen"
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
	sanctionsFile := mustGetEnv("SANCTIONS_FILE")

	upstream, err := url.Parse(upstreamURL)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		log.Error("UPSTREAM_URL must be a full URL like http://host:port", "url", upstreamURL)
		os.Exit(1)
	}

	threshold, err := strconv.Atoi(getEnv("RISK_THRESHOLD", "50"))
	if err != nil {
		log.Error("RISK_THRESHOLD must be an integer", "err", err)
		os.Exit(1)
	}

	screener, err := newScreener(sanctionsFile, threshold, log)
	if err != nil {
		log.Error("cannot build screening pipeline", "err", err)
		os.Exit(1)
	}

	// explicit timeouts protect against slowloris
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           proxy.NewHandler(upstream, screener, logger),
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

// newScreener wires the screening pipeline: sanctions list -> rules -> risk engine.
func newScreener(sanctionsFile string, threshold int, log *slog.Logger) (*screen.Screener, error) {
	list, err := sanctions.LoadListChecker(sanctionsFile)
	if err != nil {
		return nil, err
	}
	if list.Len() == 0 {
		log.Warn("sanctions list is empty, no address will be blocked", "file", sanctionsFile)
	}
	log.Info("loaded sanctions list", "file", sanctionsFile, "addresses", list.Len())

	engine, err := risk.NewEngine(threshold, rules.NewSanctioned(list))
	if err != nil {
		return nil, err
	}
	return screen.New(engine), nil
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
