// Package proxy implements the screening JSON-RPC reverse proxy.
package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spaceh3ad/tx-firewall/internal/jsonrpc"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// maxBodySize caps request bodies so a single client can't exhaust memory.
const maxBodySize = 5 << 20 // 5 MB

// Screener decides whether a decoded transaction may reach the node.
type Screener interface {
	Screen(ctx context.Context, tx *txdecode.Decoded) (risk.Verdict, error)
}

// NewHandler forwards requests to upstream. Every eth_sendRawTransaction is
// screened first; if one is blocked, or screening fails, the whole request
// (including the rest of a batch) is rejected without reaching the node.
func NewHandler(upstream *url.URL, screener Screener, logger *slog.Logger) http.Handler {
	log := logger.With("component", "proxy")
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}

		reqs, err := jsonrpc.ParseRequests(body)
		if err != nil {
			jsonrpc.WriteError(w, nil, jsonrpc.CodeParseError, "invalid JSON-RPC request")
			return
		}

		for _, req := range reqs {
			if req.Method != "eth_sendRawTransaction" {
				continue
			}

			decoded, err := txdecode.DecodeRawTransaction(req.Params)
			if err != nil {
				log.Warn("rejected undecodable transaction", "err", err)
				jsonrpc.WriteError(w, req.ID, jsonrpc.CodeInvalidParams, "invalid transaction")
				return
			}
			logTransaction(decoded, log)

			verdict, err := screener.Screen(r.Context(), decoded)
			if err != nil {
				// Fail closed: a transaction we couldn't screen is never forwarded.
				log.Error("screening failed, rejecting transaction", "hash", decoded.Tx.Hash().Hex(), "err", err)
				jsonrpc.WriteError(w, req.ID, jsonrpc.CodeTxRejected, "transaction rejected: screening failed")
				return
			}
			if verdict.Block {
				reasons := make([]string, len(verdict.Findings))
				for i, f := range verdict.Findings {
					reasons[i] = f.Reason
				}
				log.Warn("blocked transaction", "hash", decoded.Tx.Hash().Hex(), "score", verdict.Score, "reasons", reasons)
				jsonrpc.WriteError(w, req.ID, jsonrpc.CodeTxRejected, "transaction rejected: "+strings.Join(reasons, "; "))
				return
			}
		}

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	})
}

func logTransaction(d *txdecode.Decoded, log *slog.Logger) {
	tx := d.Tx

	to := "contract creation"
	if tx.To() != nil {
		to = tx.To().Hex()
	}

	// The first 4 bytes of calldata identify the called function (e.g. 0xa9059cbb = ERC-20 transfer).
	selector := "none"
	if len(tx.Data()) >= 4 {
		selector = hexutil.Encode(tx.Data()[:4])
	}

	log.Info("transaction",
		"hash", tx.Hash().Hex(),
		"type", tx.Type(),
		"from", d.From.Hex(),
		"to", to,
		"value", tx.Value().String(),
		"selector", selector,
		"nonce", tx.Nonce(),
		"chainId", tx.ChainId().String(),
	)
}
