package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spaceh3ad/tx-firewall/internal/logging"
	"github.com/spaceh3ad/tx-firewall/internal/proxy"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/sanctions"
	"github.com/spaceh3ad/tx-firewall/internal/screen"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
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

	sim, err := newSimulator(upstreamURL)
	if err != nil {
		log.Error("cannot simulate transactions on the upstream node", "err", err)
		os.Exit(1)
	}

	screener, err := newScreener(screenerConfig{
		sanctionsFile: sanctionsFile,
		oracleRPC:     os.Getenv("SANCTIONS_ORACLE_RPC"),
		threshold:     threshold,
		simulator:     sim,
	}, log)
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

// Oracle tuning: each lookup is a remote eth_call, so answers are cached.
const (
	oracleVerifyTimeout = 10 * time.Second
	oracleCallTimeout   = 2 * time.Second
	oracleCacheTTL      = 10 * time.Minute
	oracleCacheSize     = 100_000
)

// Simulation runs debug_traceCall on the upstream node for every transaction.
const (
	simulateVerifyTimeout = 10 * time.Second
	simulateTimeout       = 5 * time.Second
)

type screenerConfig struct {
	sanctionsFile string
	oracleRPC     string // empty disables the Chainalysis oracle
	threshold     int
	simulator     simulate.Simulator
}

// newSimulator connects to the upstream node and checks it supports
// debug_traceCall, so a node without the debug API fails at startup.
func newSimulator(rpcURL string) (*simulate.RPCSimulator, error) {
	ctx, cancel := context.WithTimeout(context.Background(), simulateVerifyTimeout)
	defer cancel()

	client, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, err
	}
	sim := simulate.NewRPCSimulator(client, simulateTimeout)
	if err := sim.Verify(ctx); err != nil {
		client.Close()
		return nil, err
	}
	return sim, nil
}

// newScreener wires the screening pipeline: sanctions checkers -> rules -> risk engine.
func newScreener(cfg screenerConfig, log *slog.Logger) (*screen.Screener, error) {
	list, err := sanctions.LoadListChecker(cfg.sanctionsFile)
	if err != nil {
		return nil, err
	}
	log.Info("loaded sanctions list", "file", cfg.sanctionsFile, "addresses", list.Len())

	// The in-memory list is instant, so it goes first; the oracle is only asked when the list says clean.
	checker := sanctions.AnyChecker{list}
	if cfg.oracleRPC != "" {
		oracle, err := newOracle(cfg.oracleRPC)
		if err != nil {
			return nil, err
		}
		checker = append(checker, sanctions.NewCachedChecker(oracle, oracleCacheTTL, oracleCacheSize))
		log.Info("Chainalysis sanctions oracle enabled", "contract", sanctions.ChainalysisOracle.Hex())
	} else if list.Len() == 0 {
		log.Warn("sanctions list is empty and the oracle is disabled, no address will be blocked")
	}

	engine, err := risk.NewEngine(cfg.threshold, rules.NewSanctioned(checker))
	if err != nil {
		return nil, err
	}
	return screen.New(cfg.simulator, engine), nil
}

// newOracle connects to rpcURL and checks the oracle contract exists there,
// so a wrong chain fails at startup instead of rejecting every transaction.
func newOracle(rpcURL string) (*sanctions.OracleChecker, error) {
	ctx, cancel := context.WithTimeout(context.Background(), oracleVerifyTimeout)
	defer cancel()

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("SANCTIONS_ORACLE_RPC: %w", err)
	}
	oracle := sanctions.NewOracleChecker(client, sanctions.ChainalysisOracle, oracleCallTimeout)
	if err := oracle.Verify(ctx); err != nil {
		client.Close()
		return nil, err
	}
	return oracle, nil
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
