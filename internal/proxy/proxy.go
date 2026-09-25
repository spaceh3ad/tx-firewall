// Package proxy implements the screening JSON-RPC reverse proxy.
package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/spaceh3ad/tx-firewall/internal/jsonrpc"
)

// maxBodySize caps request bodies so a single client can't exhaust memory.
const maxBodySize = 5 << 20 // 5 MB

func NewHandler(upstream *url.URL, logger *slog.Logger) http.Handler {
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
				log.Debug("rpc passthrough", "method", req.Method)
				continue
			}

		}

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	})
}
