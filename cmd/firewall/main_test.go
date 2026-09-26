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
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
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

func dial(t *testing.T, url string) *rpc.Client {
	t.Helper()
	client, err := dialUpstream(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestNewSimulator(t *testing.T) {
	trace := `{"type":"CALL","from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000000","gas":"0x0","gasUsed":"0x0","input":"0x"}`
	if _, err := newSimulator(dial(t, fakeTraceNode(t, trace))); err != nil {
		t.Errorf("node with debug API: unexpected error: %v", err)
	}
	if _, err := newSimulator(dial(t, fakeTraceNode(t, ""))); err == nil {
		t.Error("node without debug API: expected an error")
	}
	if _, err := newSimulator(dial(t, unreachableURL(t))); err == nil {
		t.Error("unreachable node: expected an error")
	}
}

// fakeHistoryNode is a JSON-RPC server at block 10000 that has pruned state older than oldest.
func fakeHistoryNode(t *testing.T, oldest uint64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(body string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,` + body + `}`))
		}
		switch req.Method {
		case "eth_blockNumber":
			reply(`"result":"0x2710"`)
		case "eth_getCode":
			var block hexutil.Uint64
			if err := json.Unmarshal(req.Params[1], &block); err == nil && uint64(block) < oldest {
				reply(`"error":{"code":-32000,"message":"missing trie node"}`)
				return
			}
			reply(`"result":"0x"`)
		default:
			reply(`"error":{"code":-32601,"message":"method not found"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestNewFreshness(t *testing.T) {
	if _, err := newFreshness(dial(t, fakeHistoryNode(t, 0)), 7200); err != nil {
		t.Errorf("archive node: unexpected error: %v", err)
	}
	pruned := fakeHistoryNode(t, 10_000-128)
	if _, err := newFreshness(dial(t, pruned), 7200); err == nil || !strings.Contains(err.Error(), "FRESH_CONTRACT_BLOCKS") {
		t.Errorf("pruned node with a long window: err = %v, want one pointing at FRESH_CONTRACT_BLOCKS", err)
	}
	if _, err := newFreshness(dial(t, pruned), 100); err != nil {
		t.Errorf("pruned node with a short window: unexpected error: %v", err)
	}
}

// staticFreshness reports the listed contracts as fresh and every other address as established.
type staticFreshness map[common.Address]bool

func (f staticFreshness) IsFreshContract(_ context.Context, addr common.Address) (bool, error) {
	return f[addr], nil
}

func (f staticFreshness) Status(_ context.Context, addr common.Address) (chainstate.Status, error) {
	if f[addr] {
		return chainstate.Fresh, nil
	}
	return chainstate.Established, nil
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
		freshness:     staticFreshness{},
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
		freshness:     staticFreshness{},
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
		s, err := newScreener(screenerConfig{sanctionsFile: writeFile(t, ""), threshold: threshold, simulator: sim, freshness: staticFreshness{}}, discard)
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

	// A proxy whose implementation was just swapped for fresh code, then upgraded again.
	impl := common.HexToAddress("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0")
	upgraded := simulate.Log{Address: factory, Topics: []common.Hash{
		crypto.Keccak256Hash([]byte("Upgraded(address)")),
		common.BytesToHash(attacker.Bytes()),
	}}
	delegateToFresh := &simulate.CallFrame{
		Type: "CALL", From: clean, To: &factory,
		Calls: []simulate.CallFrame{{Type: "DELEGATECALL", From: factory, To: &impl}},
	}
	freshUpgrade := &simulate.CallFrame{
		Type: "CALL", From: clean, To: &factory,
		Calls: []simulate.CallFrame{{Type: "DELEGATECALL", From: factory, To: &impl, Logs: []simulate.Log{upgraded}}},
	}

	// A wallet drainer: the victim approves a fresh contract for all tokens and NFTs.
	token := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	nft := common.HexToAddress("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D")
	owner, spender := common.BytesToHash(clean.Bytes()), common.BytesToHash(attacker.Bytes())
	unlimited := simulate.Log{Address: token, Topics: []common.Hash{
		crypto.Keccak256Hash([]byte("Approval(address,address,uint256)")), owner, spender,
	}, Data: common.MaxHash.Bytes()}
	allNFTs := simulate.Log{Address: nft, Topics: []common.Hash{
		crypto.Keccak256Hash([]byte("ApprovalForAll(address,address,bool)")), owner, spender,
	}, Data: common.BigToHash(common.Big1).Bytes()}
	drain := &simulate.CallFrame{
		Type: "CALL", From: clean, To: &factory,
		Calls: []simulate.CallFrame{
			{Type: "CALL", From: factory, To: &token, Logs: []simulate.Log{unlimited}},
			{Type: "CALL", From: factory, To: &nft, Logs: []simulate.Log{allNFTs}},
		},
	}
	// The same approvals given to a contract deployed and called in the transaction.
	deployAndDrain := &simulate.CallFrame{
		Type: "CALL", From: clean, To: &factory,
		Calls: append([]simulate.CallFrame{
			{Type: "CREATE", From: factory, To: &attacker},
			{Type: "CALL", From: factory, To: &attacker},
		}, drain.Calls...),
	}

	cases := map[string]struct {
		trace     *simulate.CallFrame
		fresh     staticFreshness
		wantScore int
		wantBlock bool
	}{
		"deploy and call alone":                {deployAndCall, nil, rules.WeightMedium, false},
		"deploy, call and takeover":            {takeover, nil, rules.WeightMedium + rules.WeightHigh, true},
		"delegatecall to established code":     {delegateToFresh, nil, 0, false},
		"delegatecall to fresh code":           {delegateToFresh, staticFreshness{impl: true}, rules.WeightMedium, false},
		"fresh implementation upgrades proxy":  {freshUpgrade, staticFreshness{impl: true}, rules.WeightMedium + rules.WeightHigh, true},
		"approvals to established contract":    {drain, nil, 0, false},
		"approvals to fresh contract":          {drain, staticFreshness{attacker: true}, 2 * rules.WeightMedium, false},
		"approvals to contract deployed in tx": {deployAndDrain, nil, 3 * rules.WeightMedium, true},
	}
	tx := &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: &factory}), From: clean}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := newScreener(screenerConfig{sanctionsFile: writeFile(t, ""), threshold: 50, simulator: traceSimulator{tc.trace}, freshness: tc.fresh}, discard)
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
