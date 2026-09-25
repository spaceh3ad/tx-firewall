package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Anvil's default account (0): a well-known test key, never use it for real funds.
const anvilKey0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

var discard = slog.New(slog.DiscardHandler)

// fakeNode stands in for Anvil: it records what reaches it and always returns the same response.
type fakeNode struct {
	url *url.URL

	mu       sync.Mutex
	calls    int
	lastBody []byte
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	n := &fakeNode{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		n.calls++
		n.lastBody = body
		n.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x7a69"}`)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	n.url = u
	return n
}

func (n *fakeNode) Calls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls
}

func (n *fakeNode) LastBody() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return string(n.lastBody)
}

// post sends a JSON-RPC body through the firewall handler.
func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// signedTxHex returns a valid signed EIP-1559 transfer, hex-encoded.
func signedTxHex(t *testing.T) string {
	t.Helper()
	key, err := crypto.HexToECDSA(anvilKey0)
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(31337)
	to := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(chainID), &types.DynamicFeeTx{
		ChainID:   chainID,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return hexutil.Encode(raw)
}

func TestForwardsRequestUnchanged(t *testing.T) {
	node := newFakeNode(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`
	rec := post(t, NewHandler(node.url, discard), body)

	if node.Calls() != 1 {
		t.Fatalf("node received %d requests, want 1", node.Calls())
	}
	// Guards the body-restoring step: after inspection, the node must get the exact original bytes.
	if node.LastBody() != body {
		t.Errorf("node received %q, want %q", node.LastBody(), body)
	}
	if !strings.Contains(rec.Body.String(), `"result":"0x7a69"`) {
		t.Errorf("unexpected response: %s", rec.Body.String())
	}
}

func TestForwardsValidTransaction(t *testing.T) {
	node := newFakeNode(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["` + signedTxHex(t) + `"]}`
	post(t, NewHandler(node.url, discard), body)

	if node.Calls() != 1 {
		t.Fatalf("node received %d requests, want 1", node.Calls())
	}
}

// The core security property: anything the firewall can't inspect never reaches the node.
func TestRejectsWithoutForwarding(t *testing.T) {
	cases := map[string]string{
		"invalid json":           `not json`,
		"undecodable tx":         `{"jsonrpc":"2.0","id":7,"method":"eth_sendRawTransaction","params":["0xdeadbeef"]}`,
		"missing tx params":      `{"jsonrpc":"2.0","id":7,"method":"eth_sendRawTransaction","params":[]}`,
		"bad tx hidden in batch": `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction","params":["0xdeadbeef"]}]`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			node := newFakeNode(t)
			rec := post(t, NewHandler(node.url, discard), body)

			if node.Calls() != 0 {
				t.Fatalf("request was forwarded to the node")
			}

			var resp struct {
				Error *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == nil {
				t.Errorf("expected a JSON-RPC error, got: %s", rec.Body.String())
			}
		})
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	node := newFakeNode(t)
	rec := post(t, NewHandler(node.url, discard), strings.Repeat("a", maxBodySize+1))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if node.Calls() != 0 {
		t.Fatalf("oversized request was forwarded to the node")
	}
}

func TestReturnsBadGatewayWhenNodeIsDown(t *testing.T) {
	// Start a server and close it immediately, leaving a URL where nothing is listening.
	srv := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(srv.URL)
	srv.Close()

	rec := post(t, NewHandler(u, discard), `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}
