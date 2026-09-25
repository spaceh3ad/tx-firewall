// Package jsonrpc parses incoming JSON-RPC 2.0 requests.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

// Request is a single JSON-RPC 2.0 request.
// ID and Params are kept raw: the ID is echoed back unchanged,
// and Params are decoded later depending on the method.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ParseRequests accepts either a single request (JSON object) or a batch (JSON array)
// and always returns a slice, so callers can inspect every request the same way.
func ParseRequests(body []byte) ([]Request, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty request body")
	}

	if trimmed[0] == '[' {
		var batch []Request
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			return nil, errors.New("empty batch")
		}
		return batch, nil
	}

	var req Request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return nil, err
	}
	return []Request{req}, nil
}

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError    = -32700
	CodeInvalidParams = -32602
	// CodeTxRejected is the EIP-1474 code for "transaction rejected".
	CodeTxRejected = -32003
)

// WriteError sends a JSON-RPC error response. A nil id is encoded as null,
// as required by the spec when the request id is unknown.
func WriteError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	resp.Error.Code = code
	resp.Error.Message = message

	w.Header().Set("Content-Type", "application/json")
	// JSON-RPC errors are still delivered with HTTP 200, like a regular node does.
	_ = json.NewEncoder(w).Encode(resp)
}
