package simulate

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var (
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
)

// traceNode is a JSON-RPC server answering debug_traceCall with a canned
// result or error, and recording the params it received.
type traceNode struct {
	result string // raw JSON result
	errObj string // raw JSON error object; takes precedence over result
	delay  time.Duration

	mu     sync.Mutex
	params []json.RawMessage
}

func (n *traceNode) start(t *testing.T) *rpc.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "debug_traceCall" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		n.mu.Lock()
		n.params = req.Params
		n.mu.Unlock()
		time.Sleep(n.delay)

		w.Header().Set("Content-Type", "application/json")
		if n.errObj != "" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":` + n.errObj + `}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + n.result + `}`))
	}))
	t.Cleanup(srv.Close)

	client, err := rpc.DialContext(t.Context(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func (n *traceNode) receivedParams() []json.RawMessage {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.params
}

func decoded(to *common.Address, value int64, data []byte) *txdecode.Decoded {
	return &txdecode.Decoded{
		Tx:   types.NewTx(&types.DynamicFeeTx{To: to, Gas: 100_000, Value: big.NewInt(value), Data: data}),
		From: alice,
	}
}

// A trimmed real Anvil response: a call that emits one event and makes one reverted sub-call.
const sampleTrace = `{
	"type":"CALL","from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","to":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
	"value":"0x5","gas":"0x186a0","gasUsed":"0x5208","input":"0xabcdef",
	"logs":[{"address":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8","topics":["0x0000000000000000000000000000000000000000000000000000000000000001"],"data":"0x02","position":"0x0","index":"0x0"}],
	"calls":[{"type":"DELEGATECALL","from":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8","to":"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc","gas":"0x100","gasUsed":"0x100","input":"0x","error":"execution reverted"}]
}`

func TestSimulateParsesTrace(t *testing.T) {
	node := &traceNode{result: sampleTrace}
	frame, err := NewRPCSimulator(node.start(t), time.Second).Simulate(t.Context(), decoded(&bob, 5, []byte{0xab, 0xcd, 0xef}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if frame.Type != "CALL" || frame.From != alice || frame.To == nil || *frame.To != bob {
		t.Errorf("root frame = %+v", frame)
	}
	if frame.Value.ToInt().Int64() != 5 {
		t.Errorf("value = %s, want 5", frame.Value)
	}
	if len(frame.Logs) != 1 || frame.Logs[0].Address != bob || len(frame.Logs[0].Topics) != 1 || frame.Logs[0].Data[0] != 0x02 {
		t.Errorf("logs = %+v", frame.Logs)
	}
	if len(frame.Calls) != 1 || frame.Calls[0].Type != "DELEGATECALL" || frame.Calls[0].Error != "execution reverted" {
		t.Errorf("sub-calls = %+v", frame.Calls)
	}
}

func TestSimulateSendsTransactionAndTracerConfig(t *testing.T) {
	node := &traceNode{result: sampleTrace}
	sim := NewRPCSimulator(node.start(t), time.Second)

	if _, err := sim.Simulate(t.Context(), decoded(&bob, 5, []byte{0xab, 0xcd, 0xef})); err != nil {
		t.Fatal(err)
	}
	params := node.receivedParams()
	if len(params) != 3 {
		t.Fatalf("got %d params, want 3 (call, block, config)", len(params))
	}

	var call map[string]string
	if err := json.Unmarshal(params[0], &call); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"from":  strings.ToLower(alice.Hex()),
		"to":    strings.ToLower(bob.Hex()),
		"gas":   "0x186a0",
		"value": "0x5",
		"input": "0xabcdef",
	}
	for k, v := range want {
		if strings.ToLower(call[k]) != v {
			t.Errorf("call.%s = %q, want %q", k, call[k], v)
		}
	}
	if string(params[1]) != `"latest"` {
		t.Errorf("block = %s, want \"latest\"", params[1])
	}
	if !strings.Contains(string(params[2]), `"callTracer"`) || !strings.Contains(string(params[2]), `"withLog":true`) {
		t.Errorf("tracer config = %s", params[2])
	}
}

func TestSimulateContractCreationOmitsTo(t *testing.T) {
	node := &traceNode{result: `{"type":"CREATE","from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","to":"0x5fbdb2315678afecb367f032d93f642f64180aa3","gas":"0x1","gasUsed":"0x1","input":"0x6000"}`}
	if _, err := NewRPCSimulator(node.start(t), time.Second).Simulate(t.Context(), decoded(nil, 0, []byte{0x60, 0x00})); err != nil {
		t.Fatal(err)
	}
	var call map[string]any
	if err := json.Unmarshal(node.receivedParams()[0], &call); err != nil {
		t.Fatal(err)
	}
	if _, ok := call["to"]; ok {
		t.Errorf("contract creation must not send a to field: %v", call)
	}
}

func TestSimulateErrors(t *testing.T) {
	cases := map[string]struct {
		node          *traceNode
		wantNodeError bool
	}{
		"anvil rejects tx": {&traceNode{errObj: `{"code":-32003,"message":"Insufficient funds for gas * price + value"}`}, true},
		"geth rejects tx":  {&traceNode{errObj: `{"code":-32000,"message":"insufficient funds for gas * price + value"}`}, true},
		"method not found": {&traceNode{errObj: `{"code":-32601,"message":"the method debug_traceCall does not exist"}`}, false},
		"rate limited":     {&traceNode{errObj: `{"code":-32005,"message":"limit exceeded"}`}, false},
		"empty trace":      {&traceNode{result: `{}`}, false},
		"null trace":       {&traceNode{result: `null`}, false},
		"malformed trace":  {&traceNode{result: `{"type":"CALL","from":123}`}, false},
		"timeout":          {&traceNode{result: sampleTrace, delay: 200 * time.Millisecond}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			frame, err := NewRPCSimulator(tc.node.start(t), 50*time.Millisecond).Simulate(t.Context(), decoded(&bob, 0, nil))
			if err == nil {
				t.Fatalf("expected an error, got frame %+v", frame)
			}
			var nodeErr *NodeError
			if errors.As(err, &nodeErr) != tc.wantNodeError {
				t.Errorf("err = %v (NodeError: %v), want NodeError %v", err, errors.As(err, &nodeErr), tc.wantNodeError)
			}
		})
	}
}

func TestNodeErrorKeepsNodeMessage(t *testing.T) {
	node := &traceNode{errObj: `{"code":-32003,"message":"Insufficient funds for gas * price + value"}`}
	_, err := NewRPCSimulator(node.start(t), time.Second).Simulate(t.Context(), decoded(&bob, 0, nil))

	var nodeErr *NodeError
	if !errors.As(err, &nodeErr) || nodeErr.Message != "Insufficient funds for gas * price + value" {
		t.Errorf("err = %v, want the node's message", err)
	}
}

func TestVerify(t *testing.T) {
	ok := &traceNode{result: `{"type":"CALL","from":"0x0000000000000000000000000000000000000000","gas":"0x0","gasUsed":"0x0","input":"0x"}`}
	if err := NewRPCSimulator(ok.start(t), time.Second).Verify(t.Context()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Real nodes reject a call with zero gas ("intrinsic gas too high").
	var probe map[string]string
	if err := json.Unmarshal(ok.receivedParams()[0], &probe); err != nil {
		t.Fatal(err)
	}
	if probe["gas"] == "" || probe["gas"] == "0x0" {
		t.Errorf("verify probe gas = %q, must be non-zero", probe["gas"])
	}
	missing := &traceNode{errObj: `{"code":-32601,"message":"the method debug_traceCall does not exist"}`}
	if err := NewRPCSimulator(missing.start(t), time.Second).Verify(t.Context()); err == nil {
		t.Error("expected an error for a node without the debug API")
	}
}

// For any transaction, the call arguments carry exactly its sender, recipient,
// gas, value and calldata.
func FuzzNewCallArgs(f *testing.F) {
	f.Add(bob.Bytes(), false, uint64(21_000), int64(1), []byte{})
	f.Add([]byte{}, true, uint64(0), int64(0), []byte{0x60, 0x00})

	f.Fuzz(func(t *testing.T, toBytes []byte, create bool, gas uint64, value int64, data []byte) {
		var to *common.Address
		if !create {
			addr := common.BytesToAddress(toBytes)
			to = &addr
		}
		if value < 0 {
			value = -value
		}
		tx := &txdecode.Decoded{
			Tx:   types.NewTx(&types.DynamicFeeTx{To: to, Gas: gas, Value: big.NewInt(value), Data: data}),
			From: alice,
		}

		args := newCallArgs(tx)

		if args.From != alice {
			t.Fatalf("from = %s", args.From)
		}
		if (args.To == nil) != create || (to != nil && *args.To != *to) {
			t.Fatalf("to = %v, want %v", args.To, to)
		}
		if uint64(args.Gas) != gas || args.Value.ToInt().Cmp(big.NewInt(value)) != 0 || string(args.Input) != string(data) {
			t.Fatalf("args %+v do not match tx", args)
		}
		if _, err := json.Marshal(args); err != nil {
			t.Fatalf("args do not marshal: %v", err)
		}
	})
}

// Whatever JSON the node returns, decoding a trace must not panic.
func FuzzCallFrameJSON(f *testing.F) {
	f.Add([]byte(sampleTrace))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"calls":[{"calls":[{}]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var frame CallFrame
		_ = json.Unmarshal(data, &frame)
	})
}
