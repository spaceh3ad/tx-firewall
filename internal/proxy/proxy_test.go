package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spaceh3ad/tx-firewall/internal/jsonrpc"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Anvil's default account (0): a well-known test key, never use it for real funds.
const anvilKey0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

var discard = slog.New(slog.DiscardHandler)

// fakeScreener returns a fixed verdict (or error) and records every sender it screened.
type fakeScreener struct {
	verdict risk.Verdict
	err     error

	mu      sync.Mutex
	senders []common.Address
}

func (s *fakeScreener) Screen(_ context.Context, tx *txdecode.Decoded) (risk.Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senders = append(s.senders, tx.From)
	return s.verdict, s.err
}

func (s *fakeScreener) Senders() []common.Address {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.senders)
}

var allowAll = &fakeScreener{}

func blocking(reasons ...string) *fakeScreener {
	v := risk.Verdict{Block: true}
	for _, r := range reasons {
		v.Findings = append(v.Findings, rules.Finding{Rule: "test", HardBlock: true, Reason: r})
	}
	return &fakeScreener{verdict: v}
}

// rpcError decodes a single JSON-RPC error response, failing the test if there is none.
func rpcError(t *testing.T, rec *httptest.ResponseRecorder) (code int, message string) {
	t.Helper()
	var resp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error, got: %s", rec.Body.String())
	}
	return resp.Error.Code, resp.Error.Message
}

// fakeNode stands in for Anvil: it records what reaches it and always returns the same response.
type fakeNode struct {
	url *url.URL

	mu       sync.Mutex
	calls    int
	lastBody []byte
}

func newFakeNode(t testing.TB) *fakeNode {
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
func signedTxHex(t testing.TB) string {
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
	rec := post(t, NewHandler(node.url, allowAll, discard), body)

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
	post(t, NewHandler(node.url, allowAll, discard), body)

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
			rec := post(t, NewHandler(node.url, allowAll, discard), body)

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
	rec := post(t, NewHandler(node.url, allowAll, discard), strings.Repeat("a", maxBodySize+1))

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

	rec := post(t, NewHandler(u, allowAll, discard), `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func sendTxBody(t testing.TB) string {
	t.Helper()
	return `{"jsonrpc":"2.0","id":42,"method":"eth_sendRawTransaction","params":["` + signedTxHex(t) + `"]}`
}

func TestScreenerReceivesRecoveredSender(t *testing.T) {
	node := newFakeNode(t)
	screener := &fakeScreener{}
	post(t, NewHandler(node.url, screener, discard), sendTxBody(t))

	want := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266") // address of anvilKey0
	if got := screener.Senders(); len(got) != 1 || got[0] != want {
		t.Errorf("screened senders = %v, want [%s]", got, want)
	}
	if node.Calls() != 1 {
		t.Errorf("allowed transaction was not forwarded")
	}
}

func TestBlockedTransactionIsRejected(t *testing.T) {
	node := newFakeNode(t)
	rec := post(t, NewHandler(node.url, blocking("sanctioned address 0xabc", "second reason"), discard), sendTxBody(t))

	if node.Calls() != 0 {
		t.Fatal("blocked transaction was forwarded to the node")
	}
	code, msg := rpcError(t, rec)
	if code != jsonrpc.CodeTxRejected {
		t.Errorf("code = %d, want %d", code, jsonrpc.CodeTxRejected)
	}
	for _, reason := range []string{"sanctioned address 0xabc", "second reason"} {
		if !strings.Contains(msg, reason) {
			t.Errorf("message %q does not include reason %q", msg, reason)
		}
	}
	if !strings.Contains(rec.Body.String(), `"id":42`) {
		t.Errorf("response does not echo the request id: %s", rec.Body.String())
	}
}

// Fail closed: if screening itself fails, the transaction must not go through.
func TestScreeningFailureRejects(t *testing.T) {
	node := newFakeNode(t)
	screener := &fakeScreener{err: errors.New("dial tcp 10.0.0.5:8545: connection refused")}
	rec := post(t, NewHandler(node.url, screener, discard), sendTxBody(t))

	if node.Calls() != 0 {
		t.Fatal("unscreened transaction was forwarded to the node")
	}
	code, msg := rpcError(t, rec)
	if code != jsonrpc.CodeTxRejected {
		t.Errorf("code = %d, want %d", code, jsonrpc.CodeTxRejected)
	}
	if strings.Contains(msg, "10.0.0.5") {
		t.Errorf("internal error details leaked to the client: %q", msg)
	}
}

func TestBlockedTransactionInBatchRejectsWholeBatch(t *testing.T) {
	node := newFakeNode(t)
	body := `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},` + sendTxBody(t) + `]`
	post(t, NewHandler(node.url, blocking("bad"), discard), body)

	if node.Calls() != 0 {
		t.Fatal("batch with a blocked transaction was forwarded to the node")
	}
}

func TestOtherMethodsAreNotScreened(t *testing.T) {
	node := newFakeNode(t)
	screener := blocking("would block")
	post(t, NewHandler(node.url, screener, discard), `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`)

	if len(screener.Senders()) != 0 {
		t.Error("a non-transaction request was screened")
	}
	if node.Calls() != 1 {
		t.Error("a non-transaction request was not forwarded")
	}
}

// For any screening outcome and any number of plain requests batched before the
// transaction, the request reaches the node exactly when screening allowed it.
func FuzzForwardsOnlyAllowedTransactions(f *testing.F) {
	f.Add(false, false, uint8(0))
	f.Add(true, false, uint8(0))
	f.Add(false, true, uint8(3))
	f.Add(true, true, uint8(1))

	// One node for all iterations: a fresh server per iteration exhausts local
	// connections under fuzzing and makes the proxy fail with 502.
	node := newFakeNode(f)
	txBody := sendTxBody(f)

	f.Fuzz(func(t *testing.T, block, fail bool, before uint8) {
		screener := &fakeScreener{verdict: risk.Verdict{Block: block}}
		if fail {
			screener.err = errors.New("screening failed")
		}

		parts := make([]string, 0, int(before%8)+1)
		for i := range int(before % 8) {
			parts = append(parts, `{"jsonrpc":"2.0","id":`+strconv.Itoa(i+100)+`,"method":"eth_chainId"}`)
		}
		body := txBody
		if len(parts) > 0 {
			body = "[" + strings.Join(append(parts, body), ",") + "]"
		}

		callsBefore := node.Calls()
		rec := post(t, NewHandler(node.url, screener, discard), body)

		wantForwarded := !block && !fail
		if got := node.Calls() == callsBefore+1; got != wantForwarded {
			t.Fatalf("forwarded = %v, want %v (block=%v fail=%v batch=%d); response %d %s",
				got, wantForwarded, block, fail, len(parts), rec.Code, rec.Body.String())
		}
	})
}
