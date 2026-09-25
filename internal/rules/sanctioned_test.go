package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/sanctions"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var (
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	carol = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
)

func txFrom(from common.Address, to *common.Address) *analysis.Analysis {
	return analysis.FromTx(&txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: to}), From: from})
}

// failingChecker simulates a checker whose backend (e.g. an RPC oracle) is down.
type failingChecker struct{}

func (failingChecker) IsSanctioned(context.Context, common.Address) (bool, error) {
	return false, errors.New("oracle unavailable")
}

func TestSanctioned(t *testing.T) {
	rule := NewSanctioned(sanctions.NewListChecker([]common.Address{carol}))

	cases := map[string]struct {
		a         *analysis.Analysis
		wantAddrs []common.Address
	}{
		"clean transfer":           {txFrom(alice, &bob), nil},
		"sanctioned sender":        {txFrom(carol, &bob), []common.Address{carol}},
		"sanctioned recipient":     {txFrom(alice, &carol), []common.Address{carol}},
		"sanctioned self transfer": {txFrom(carol, &carol), []common.Address{carol}},
		"clean contract creation":  {txFrom(alice, nil), nil},
		"sanctioned deployer":      {txFrom(carol, nil), []common.Address{carol}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := rule.Evaluate(t.Context(), tc.a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != len(tc.wantAddrs) {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), len(tc.wantAddrs), findings)
			}
			for i, f := range findings {
				if !f.HardBlock {
					t.Error("sanctions finding must be a hard block")
				}
				if f.Rule != rule.Name() {
					t.Errorf("rule = %q, want %q", f.Rule, rule.Name())
				}
				if !strings.Contains(f.Reason, tc.wantAddrs[i].Hex()) {
					t.Errorf("reason %q does not name %s", f.Reason, tc.wantAddrs[i].Hex())
				}
			}
		})
	}
}

func TestSanctionedPropagatesCheckerError(t *testing.T) {
	findings, err := NewSanctioned(failingChecker{}).Evaluate(t.Context(), txFrom(alice, &bob))
	if err == nil {
		t.Fatal("expected an error when the checker fails")
	}
	if findings != nil {
		t.Errorf("findings must be nil on error, got %+v", findings)
	}
}

// Every sanctioned address in the analysis yields exactly one hard-block finding,
// and clean addresses yield none.
func FuzzSanctioned(f *testing.F) {
	f.Add(alice.Bytes(), bob.Bytes(), uint8(0))
	f.Add(alice.Bytes(), bob.Bytes(), uint8(3))
	f.Add(alice.Bytes(), alice.Bytes(), uint8(1))

	f.Fuzz(func(t *testing.T, fromBytes, toBytes []byte, listMask uint8) {
		from, to := common.BytesToAddress(fromBytes), common.BytesToAddress(toBytes)

		var listed []common.Address
		if listMask&1 != 0 {
			listed = append(listed, from)
		}
		if listMask&2 != 0 {
			listed = append(listed, to)
		}
		a := txFrom(from, &to)

		findings, err := NewSanctioned(sanctions.NewListChecker(listed)).Evaluate(t.Context(), a)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := 0
		for _, addr := range a.Addresses {
			if (listMask&1 != 0 && addr == from) || (listMask&2 != 0 && addr == to) {
				want++
			}
		}
		if len(findings) != want {
			t.Fatalf("got %d findings, want %d", len(findings), want)
		}
		for _, f := range findings {
			if !f.HardBlock {
				t.Fatal("sanctions finding must be a hard block")
			}
		}
	})
}
