package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/screen"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var (
	discard = slog.New(slog.DiscardHandler)

	clean        = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	listed       = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	oracleListed = common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906")
)

// plainSimulator traces every transaction as a simple call with no events.
type plainSimulator struct{}

func (plainSimulator) Simulate(_ context.Context, tx *txdecode.Decoded) (*simulate.CallFrame, error) {
	return &simulate.CallFrame{Type: "CALL", From: tx.From, To: tx.Tx.To()}, nil
}

// fakeTraceNode is a JSON-RPC server answering debug_traceCall with result, or
// with a "method not found" error when result is empty.
func fakeTraceNode(t *testing.T, result string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if result == "" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32601,"message":"the method debug_traceCall does not exist"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestNewSimulator(t *testing.T) {
	trace := `{"type":"CALL","from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000000","gas":"0x0","gasUsed":"0x0","input":"0x"}`
	if _, err := newSimulator(fakeTraceNode(t, trace)); err != nil {
		t.Errorf("node with debug API: unexpected error: %v", err)
	}
	if _, err := newSimulator(fakeTraceNode(t, "")); err == nil {
		t.Error("node without debug API: expected an error")
	}
	if _, err := newSimulator(unreachableURL(t)); err == nil {
		t.Error("unreachable node: expected an error")
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sanctions.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeOracleNode is a JSON-RPC server that plays a chain with the Chainalysis
// oracle deployed (or not), reporting oracleListed as sanctioned.
func fakeOracleNode(t *testing.T, deployed bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var result string
		switch req.Method {
		case "eth_getCode":
			result = "0x"
			if deployed {
				result = "0x6080"
			}
		case "eth_call":
			var call struct {
				Input hexutil.Bytes `json:"input"`
			}
			if err := json.Unmarshal(req.Params[0], &call); err != nil || len(call.Input) != 36 {
				http.Error(w, "bad eth_call", http.StatusBadRequest)
				return
			}
			answer := make([]byte, 32)
			if common.BytesToAddress(call.Input[4:]) == oracleListed {
				answer[31] = 1
			}
			result = hexutil.Encode(answer)
		default:
			http.Error(w, "unexpected method "+req.Method, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func assertBlocks(t *testing.T, s *screen.Screener, want map[common.Address]bool) {
	t.Helper()
	for from, wantBlock := range want {
		v, err := s.Screen(t.Context(), &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{}), From: from})
		if err != nil {
			t.Fatalf("sender %s: unexpected error: %v", from, err)
		}
		if v.Block != wantBlock {
			t.Errorf("sender %s: block = %v, want %v", from, v.Block, wantBlock)
		}
	}
}

func TestNewScreenerWithListOnly(t *testing.T) {
	s, err := newScreener(screenerConfig{
		sanctionsFile: writeFile(t, "# test list\n"+listed.Hex()+"\n"),
		threshold:     50,
		simulator:     plainSimulator{},
	}, discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBlocks(t, s, map[common.Address]bool{listed: true, clean: false, oracleListed: false})
}

func TestNewScreenerWithOracle(t *testing.T) {
	s, err := newScreener(screenerConfig{
		sanctionsFile: writeFile(t, listed.Hex()+"\n"),
		oracleRPC:     fakeOracleNode(t, true),
		threshold:     50,
		simulator:     plainSimulator{},
	}, discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBlocks(t, s, map[common.Address]bool{listed: true, oracleListed: true, clean: false})
}

func TestNewScreenerRejectsBadConfig(t *testing.T) {
	cases := map[string]screenerConfig{
		"missing file":           {sanctionsFile: filepath.Join(t.TempDir(), "missing.txt"), threshold: 50},
		"malformed list":         {sanctionsFile: writeFile(t, "not-an-address\n"), threshold: 50},
		"zero threshold":         {sanctionsFile: writeFile(t, ""), threshold: 0},
		"oracle not on chain":    {sanctionsFile: writeFile(t, ""), oracleRPC: fakeOracleNode(t, false), threshold: 50},
		"unsupported rpc url":    {sanctionsFile: writeFile(t, ""), oracleRPC: "ftp://example.com", threshold: 50},
		"unreachable oracle rpc": {sanctionsFile: writeFile(t, ""), oracleRPC: unreachableURL(t), threshold: 50},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newScreener(cfg, discard); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// unreachableURL returns the URL of a server that has already shut down.
func unreachableURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return url
}

// The shipped list must stay loadable: a typo in it would stop the firewall from starting.
// eventSimulator traces every transaction as a call to target that emits one log.
type eventSimulator struct {
	target common.Address
	topics []common.Hash
}

func (s eventSimulator) Simulate(_ context.Context, tx *txdecode.Decoded) (*simulate.CallFrame, error) {
	return &simulate.CallFrame{
		Type: "CALL", From: tx.From, To: &s.target,
		Logs: []simulate.Log{{Address: s.target, Topics: s.topics}},
	}, nil
}

func TestNewScreenerFlagsPrivilegeChange(t *testing.T) {
	vault := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	sim := eventSimulator{target: vault, topics: []common.Hash{
		crypto.Keccak256Hash([]byte("OwnershipTransferred(address,address)")),
		common.BytesToHash(clean.Bytes()),
		common.BytesToHash(listed.Bytes()),
	}}
	tx := &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: &vault}), From: clean}

	for threshold, wantBlock := range map[int]bool{50: false, 40: true} {
		s, err := newScreener(screenerConfig{sanctionsFile: writeFile(t, ""), threshold: threshold, simulator: sim}, discard)
		if err != nil {
			t.Fatal(err)
		}
		v, err := s.Screen(t.Context(), tx)
		if err != nil {
			t.Fatal(err)
		}
		if v.Score != rules.WeightHigh || v.Block != wantBlock {
			t.Errorf("threshold %d: verdict = %+v, want score %d and block %v", threshold, v, rules.WeightHigh, wantBlock)
		}
	}
}

// traceSimulator returns the same trace for every transaction.
type traceSimulator struct{ trace *simulate.CallFrame }

func (s traceSimulator) Simulate(context.Context, *txdecode.Decoded) (*simulate.CallFrame, error) {
	return s.trace, nil
}

// Signals add up: deploying and calling a contract (medium) that takes over
// an existing contract (high) reaches the default threshold of 50.
func TestNewScreenerCombinesRules(t *testing.T) {
	factory := common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	attacker := common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")
	vault := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	ownershipTransferred := simulate.Log{Address: vault, Topics: []common.Hash{
		crypto.Keccak256Hash([]byte("OwnershipTransferred(address,address)")),
		common.BytesToHash(factory.Bytes()),
		common.BytesToHash(attacker.Bytes()),
	}}

	deployAndCall := &simulate.CallFrame{
		Type: "CALL", From: clean, To: &factory,
		Calls: []simulate.CallFrame{
			{Type: "CREATE", From: factory, To: &attacker},
			{Type: "CALL", From: factory, To: &attacker},
		},
	}
	takeover := &simulate.CallFrame{
		Type: "CALL", From: clean, To: &factory,
		Calls: []simulate.CallFrame{
			{Type: "CREATE", From: factory, To: &attacker},
			{Type: "CALL", From: factory, To: &attacker, Calls: []simulate.CallFrame{
				{Type: "CALL", From: attacker, To: &vault, Logs: []simulate.Log{ownershipTransferred}},
			}},
		},
	}

	cases := map[string]struct {
		trace     *simulate.CallFrame
		wantScore int
		wantBlock bool
	}{
		"deploy and call alone":     {deployAndCall, rules.WeightMedium, false},
		"deploy, call and takeover": {takeover, rules.WeightMedium + rules.WeightHigh, true},
	}
	tx := &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: &factory}), From: clean}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := newScreener(screenerConfig{sanctionsFile: writeFile(t, ""), threshold: 50, simulator: traceSimulator{tc.trace}}, discard)
			if err != nil {
				t.Fatal(err)
			}
			v, err := s.Screen(t.Context(), tx)
			if err != nil {
				t.Fatal(err)
			}
			if v.Score != tc.wantScore || v.Block != tc.wantBlock {
				t.Errorf("verdict = %+v, want score %d and block %v", v, tc.wantScore, tc.wantBlock)
			}
		})
	}
}

func TestShippedSanctionsListLoads(t *testing.T) {
	path := filepath.Join("..", "..", "config", "sanctions.txt")
	if _, err := newScreener(screenerConfig{sanctionsFile: path, threshold: 50}, discard); err != nil {
		t.Fatalf("config/sanctions.txt does not load: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "0x0330070FD38Ec3bB94F58FA55D40368271E9e54A") {
		t.Error("shipped list is missing a known OFAC entry; was it truncated?")
	}
}
