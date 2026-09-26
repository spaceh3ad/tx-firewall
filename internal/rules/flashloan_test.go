package rules

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
)

var lender = common.HexToAddress("0xBA12222222228d8Ba445958a75a0704d566BF2C8")

func loan(l common.Address) analysis.FlashLoan {
	return analysis.FlashLoan{Lender: l, Token: usdc, Amount: big.NewInt(1_000_000), Source: "Balancer V2"}
}

func TestFlashLoanOutflow(t *testing.T) {
	status := map[common.Address]chainstate.Status{vault: chainstate.Established, lender: chainstate.Established}
	cases := map[string]struct {
		loans []analysis.FlashLoan
		flows []analysis.Flow
		bal   *fakeBalances
		want  []string // substrings; empty: no finding
	}{
		"flash loan and a drained vault": {
			[]analysis.FlashLoan{loan(lender)},
			[]analysis.Flow{flow(usdc, vault, 900, 0)},
			balances(usdc, vault, 1000),
			[]string{"flash loan from " + lender.Hex() + " (Balancer V2)", "90% of token " + usdc.Hex() + " held by " + vault.Hex()},
		},
		"drained vault without a flash loan": {
			nil, []analysis.Flow{flow(usdc, vault, 900, 0)}, balances(usdc, vault, 1000), nil,
		},
		"flash loan without an outflow": {
			[]analysis.FlashLoan{loan(lender)}, []analysis.Flow{flow(usdc, vault, 100, 0)}, balances(usdc, vault, 1000), nil,
		},
		"only the lender's own balance moves": {
			[]analysis.FlashLoan{loan(lender)}, []analysis.Flow{flow(usdc, lender, 900, 0)}, balances(usdc, lender, 1000), nil,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, err := NewOutflowDetector(newFakeStatus(status), tc.bal, 50)
			if err != nil {
				t.Fatal(err)
			}
			a := withFlows(nil, tc.flows...)
			a.FlashLoans = tc.loans

			rule := NewFlashLoanOutflow(d)
			findings, err := rule.Evaluate(t.Context(), a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tc.want) == 0 {
				if len(findings) != 0 {
					t.Errorf("unexpected findings: %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Weight != WeightHigh || f.HardBlock || f.Rule != rule.Name() {
				t.Errorf("finding = %+v, want a high-weight %s finding", f, rule.Name())
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Reason, want) {
					t.Errorf("reason %q does not contain %q", f.Reason, want)
				}
			}
		})
	}
}

func TestFlashLoanOutflowSkipsLookupsWithoutLoan(t *testing.T) {
	bal := balances(usdc, vault, 1000)
	status := newFakeStatus(map[common.Address]chainstate.Status{vault: chainstate.Established})
	d, _ := NewOutflowDetector(status, bal, 50)

	if _, err := NewFlashLoanOutflow(d).Evaluate(t.Context(), withFlows(nil, flow(usdc, vault, 900, 0))); err != nil {
		t.Fatal(err)
	}
	if bal.calls != 0 || len(status.calls) != 0 {
		t.Error("looked up balances for a transaction without a flash loan")
	}
}

// Reference model: fires exactly when there is a loan and some holder other
// than every lender loses more than half of an asset it held.
func FuzzFlashLoanOutflow(f *testing.F) {
	f.Add(uint8(0x01), uint8(0x02), uint64(900))
	f.Add(uint8(0x01), uint8(0x01), uint64(900))
	f.Add(uint8(0x00), uint8(0x02), uint64(900))
	f.Add(uint8(0x03), uint8(0x03), uint64(400))

	holders := []common.Address{lender, vault}
	status := map[common.Address]chainstate.Status{lender: chainstate.Established, vault: chainstate.Established}

	f.Fuzz(func(t *testing.T, lenderMask, drainedMask uint8, out uint64) {
		var loans []analysis.FlashLoan
		var flows []analysis.Flow
		bal := balances()
		wantFire := false
		isLender := map[common.Address]bool{}
		for i, h := range holders {
			if lenderMask&(1<<i) != 0 {
				loans = append(loans, loan(h))
				isLender[h] = true
			}
		}
		for i, h := range holders {
			if drainedMask&(1<<i) != 0 {
				flows = append(flows, analysis.Flow{Asset: usdc, Holder: h, Out: new(big.Int).SetUint64(out), In: new(big.Int)})
				bal.balances[[2]common.Address{usdc, h}] = big.NewInt(1000)
				// out > 500 is "more than 50% of 1000"; computed without uint64 overflow.
				if out > 500 && !isLender[h] {
					wantFire = true
				}
			}
		}
		wantFire = wantFire && len(loans) > 0

		d, _ := NewOutflowDetector(newFakeStatus(status), bal, 50)
		a := withFlows(nil, flows...)
		a.FlashLoans = loans
		findings, err := NewFlashLoanOutflow(d).Evaluate(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findings) == 1; got != wantFire || len(findings) > 1 {
			t.Fatalf("got %d findings, want fire=%v (lenders %b, drained %b, out %d)", len(findings), wantFire, lenderMask, drainedMask, out)
		}
	})
}
