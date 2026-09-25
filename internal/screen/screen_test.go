package screen

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/sanctions"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var (
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	carol = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
)

// fakeSimulator returns a fixed trace (or error) and records what it simulated.
type fakeSimulator struct {
	trace *simulate.CallFrame
	err   error
	calls int
}

func (f *fakeSimulator) Simulate(_ context.Context, tx *txdecode.Decoded) (*simulate.CallFrame, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.trace != nil {
		return f.trace, nil
	}
	return &simulate.CallFrame{Type: "CALL", From: tx.From, To: tx.Tx.To()}, nil
}

// newScreener wires the real rules and engine (threshold 50) with carol on the sanctions list.
func newScreener(t testing.TB, sim simulate.Simulator) *Screener {
	t.Helper()
	engine, err := risk.NewEngine(50,
		rules.NewSanctioned(sanctions.NewListChecker([]common.Address{carol})),
		rules.NewPrivilegeChange(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return New(sim, engine)
}

func decoded(from common.Address, to *common.Address) *txdecode.Decoded {
	return &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: to}), From: from}
}

func TestScreenSanctions(t *testing.T) {
	cases := map[string]struct {
		tx        *txdecode.Decoded
		wantBlock bool
	}{
		"clean transfer":       {decoded(alice, &bob), false},
		"sanctioned sender":    {decoded(carol, &bob), true},
		"sanctioned recipient": {decoded(alice, &carol), true},
		"clean deployment":     {decoded(alice, nil), false},
	}
	s := newScreener(t, &fakeSimulator{})
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := s.Screen(t.Context(), tc.tx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.Block != tc.wantBlock {
				t.Errorf("block = %v, want %v (findings %+v)", v.Block, tc.wantBlock, v.Findings)
			}
			if tc.wantBlock && len(v.Findings) == 0 {
				t.Error("a blocked verdict must explain itself with findings")
			}
		})
	}
}

func TestScreenUsesSimulatedEvents(t *testing.T) {
	topic := crypto.Keccak256Hash([]byte("OwnershipTransferred(address,address)"))
	sim := &fakeSimulator{trace: &simulate.CallFrame{
		Type: "CALL", From: alice, To: &bob,
		Logs: []simulate.Log{{Address: bob, Topics: []common.Hash{topic, common.BytesToHash(alice.Bytes()), common.BytesToHash(carol.Bytes())}}},
	}}

	v, err := newScreener(t, sim).Screen(t.Context(), decoded(alice, &bob))
	if err != nil {
		t.Fatal(err)
	}
	if v.Score != rules.WeightHigh || v.Block {
		t.Errorf("verdict = %+v, want a flagged but allowed transaction", v)
	}
	if sim.calls != 1 {
		t.Errorf("simulator called %d times, want 1", sim.calls)
	}
}

func TestScreenBlocksWhatTheNodeRejects(t *testing.T) {
	sim := &fakeSimulator{err: &simulate.NodeError{Message: "Insufficient funds for gas * price + value"}}
	v, err := newScreener(t, sim).Screen(t.Context(), decoded(alice, &bob))
	if err != nil {
		t.Fatalf("a node rejection is a verdict, not an error: %v", err)
	}
	if !v.Block || len(v.Findings) != 1 || !v.Findings[0].HardBlock {
		t.Fatalf("verdict = %+v, want one hard block", v)
	}
	if !strings.Contains(v.Findings[0].Reason, "Insufficient funds") {
		t.Errorf("reason %q does not carry the node's message", v.Findings[0].Reason)
	}
}

func TestScreenFailsWhenSimulationFails(t *testing.T) {
	boom := errors.New("dial tcp: connection refused")
	_, err := newScreener(t, &fakeSimulator{err: boom}).Screen(t.Context(), decoded(alice, &bob))
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap %v", err, boom)
	}
}

// Whatever the sender and recipient, the verdict blocks exactly when carol is involved.
func FuzzScreen(f *testing.F) {
	f.Add(alice.Bytes(), bob.Bytes(), false)
	f.Add(carol.Bytes(), bob.Bytes(), false)
	f.Add(alice.Bytes(), carol.Bytes(), false)
	f.Add(carol.Bytes(), []byte{}, true)

	s := newScreener(f, &fakeSimulator{})
	f.Fuzz(func(t *testing.T, fromBytes, toBytes []byte, create bool) {
		from := common.BytesToAddress(fromBytes)
		var to *common.Address
		if !create {
			addr := common.BytesToAddress(toBytes)
			to = &addr
		}

		v, err := s.Screen(t.Context(), decoded(from, to))
		if err != nil {
			t.Fatal(err)
		}
		want := from == carol || (to != nil && *to == carol)
		if v.Block != want {
			t.Fatalf("block = %v, want %v for %s -> %v", v.Block, want, from, to)
		}
	})
}
