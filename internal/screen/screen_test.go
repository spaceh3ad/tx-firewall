package screen

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/sanctions"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var (
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	carol = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
)

// newScreener wires the real pipeline with carol on the sanctions list.
func newScreener(t *testing.T) *Screener {
	t.Helper()
	engine, err := risk.NewEngine(50, rules.NewSanctioned(sanctions.NewListChecker([]common.Address{carol})))
	if err != nil {
		t.Fatal(err)
	}
	return New(engine)
}

func decoded(from common.Address, to *common.Address) *txdecode.Decoded {
	return &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: to}), From: from}
}

func TestScreen(t *testing.T) {
	cases := map[string]struct {
		tx        *txdecode.Decoded
		wantBlock bool
	}{
		"clean transfer":       {decoded(alice, &bob), false},
		"sanctioned sender":    {decoded(carol, &bob), true},
		"sanctioned recipient": {decoded(alice, &carol), true},
		"clean deployment":     {decoded(alice, nil), false},
	}
	s := newScreener(t)
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

// Whatever the sender and recipient, the verdict blocks exactly when carol is involved.
func FuzzScreen(f *testing.F) {
	f.Add(alice.Bytes(), bob.Bytes(), false)
	f.Add(carol.Bytes(), bob.Bytes(), false)
	f.Add(alice.Bytes(), carol.Bytes(), false)
	f.Add(carol.Bytes(), []byte{}, true)

	f.Fuzz(func(t *testing.T, fromBytes, toBytes []byte, create bool) {
		from := common.BytesToAddress(fromBytes)
		var to *common.Address
		if !create {
			addr := common.BytesToAddress(toBytes)
			to = &addr
		}

		v, err := newScreener(t).Screen(t.Context(), decoded(from, to))
		if err != nil {
			t.Fatal(err)
		}
		want := from == carol || (to != nil && *to == carol)
		if v.Block != want {
			t.Fatalf("block = %v, want %v for %s -> %v", v.Block, want, from, to)
		}
	})
}
