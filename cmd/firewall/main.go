package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

const maxBodySize = 5 << 20
const upstreamURL = "http://127.0.0.1:8545"
const listenAddr = ":8546"

func main() {
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		slog.Error("invalid upstream URL", "err", err)
		os.Exit(1)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}

		slog.Info("request", "method", r.Method, "url", r.URL.String(), "body", string(body))

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	})

	slog.Info("proxy listening", "addr", listenAddr, "upstream", upstreamURL)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
