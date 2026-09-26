package rules

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
)

// fakeBalances answers from a fixed table; missing entries are unmeasurable.
type fakeBalances struct {
	balances map[[2]common.Address]*big.Int // {asset, holder}
	err      error
	calls    int
}

func (f *fakeBalances) Balance(_ context.Context, asset, holder common.Address) (*big.Int, bool, error) {
	f.calls++
	if f.err != nil {
		return nil, false, f.err
	}
	b, ok := f.balances[[2]common.Address{asset, holder}]
	return b, ok, nil
}

func balances(entries ...any) *fakeBalances {
	f := &fakeBalances{balances: map[[2]common.Address]*big.Int{}}
	for i := 0; i < len(entries); i += 3 {
		f.balances[[2]common.Address{entries[i].(common.Address), entries[i+1].(common.Address)}] = big.NewInt(int64(entries[i+2].(int)))
	}
	return f
}

func flow(asset, holder common.Address, out, in int64) analysis.Flow {
	return analysis.Flow{Asset: asset, Holder: holder, Out: big.NewInt(out), In: big.NewInt(in)}
}

func withFlows(created []common.Address, flows ...analysis.Flow) *analysis.Analysis {
	a := txFrom(alice, &vault)
	a.Created = created
	a.Flows = flows
	return a
}

// contracts: vault and the usdc token are established contracts; alice has no code.
var contractStatus = map[common.Address]chainstate.Status{vault: chainstate.Established, usdc: chainstate.Established, child: chainstate.Fresh}

func mustDetector(t testing.TB, bal *fakeBalances, percent int) *OutflowDetector {
	t.Helper()
	d, err := NewOutflowDetector(newFakeStatus(contractStatus), bal, percent)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNewOutflowDetectorRejectsBadPercent(t *testing.T) {
	for _, p := range []int{0, -5, 101} {
		if _, err := NewOutflowDetector(newFakeStatus(nil), balances(), p); err == nil {
			t.Errorf("percent %d: expected an error", p)
		}
	}
}

func TestLargeOutflow(t *testing.T) {
	cases := map[string]struct {
		a    *analysis.Analysis
		bal  *fakeBalances
		want []string // substrings; empty: no finding
	}{
		"vault drained of 60%": {
			withFlows(nil, flow(usdc, vault, 600, 0)), balances(usdc, vault, 1000),
			[]string{"60% of token " + usdc.Hex() + " held by " + vault.Hex(), "(600 of 1000)"},
		},
		"exactly 50% is not more than 50%": {withFlows(nil, flow(usdc, vault, 500, 0)), balances(usdc, vault, 1000), nil},
		"gross outflow, small net": {
			withFlows(nil, flow(usdc, vault, 900, 800)), balances(usdc, vault, 1000), nil,
		},
		"ETH drained": {
			withFlows(nil, flow(analysis.ETH, vault, 9, 0)), balances(analysis.ETH, vault, 10),
			[]string{"90% of ETH held by " + vault.Hex()},
		},
		"EOA sends everything": {withFlows(nil, flow(usdc, alice, 1000, 0)), balances(usdc, alice, 1000), nil},
		"fresh contract counts too": {
			withFlows(nil, flow(usdc, child, 800, 0)), balances(usdc, child, 1000), []string{child.Hex()},
		},
		"contract created in this tx": {withFlows([]common.Address{child2}, flow(usdc, child2, 800, 0)), balances(usdc, child2, 0), nil},
		"unmeasurable token":          {withFlows(nil, flow(usdc, vault, 800, 0)), balances(), nil},
		"empty balance before":        {withFlows(nil, flow(usdc, vault, 800, 0)), balances(usdc, vault, 0), nil},
		"mint from zero address":      {withFlows(nil, flow(usdc, common.Address{}, 800, 0)), balances(usdc, common.Address{}, 1), nil},
		"two assets drained, one finding": {
			withFlows(nil, flow(usdc, vault, 600, 0), flow(analysis.ETH, vault, 9, 0)),
			balances(usdc, vault, 1000, analysis.ETH, vault, 10),
			[]string{"token " + usdc.Hex(), "ETH held by"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rule := NewLargeOutflow(mustDetector(t, tc.bal, 50))
			findings, err := rule.Evaluate(t.Context(), tc.a)
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

func TestLargeOutflowSkipsLookupsForGains(t *testing.T) {
	bal := balances(usdc, vault, 1000)
	status := newFakeStatus(contractStatus)
	d, _ := NewOutflowDetector(status, bal, 50)
	a := withFlows(nil, flow(usdc, vault, 100, 500), flow(usdc, alice, 400, 0))

	if _, err := d.Find(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if status.calls[vault] != 0 {
		t.Error("looked up a holder that gained tokens")
	}
	if bal.calls != 0 {
		t.Error("read a balance for an EOA")
	}
}

func TestLargeOutflowPropagatesErrors(t *testing.T) {
	failingBalances := balances()
	failingBalances.err = errors.New("node unavailable")
	failingStatus := newFakeStatus(nil)
	failingStatus.err = errors.New("node unavailable")

	a := withFlows(nil, flow(usdc, vault, 600, 0))
	for name, d := range map[string]*OutflowDetector{
		"balance": {status: newFakeStatus(contractStatus), balances: failingBalances, percent: 50},
		"status":  {status: failingStatus, balances: balances(usdc, vault, 1000), percent: 50},
	} {
		if findings, err := NewLargeOutflow(d).Evaluate(t.Context(), a); err == nil || findings != nil {
			t.Errorf("%s failure: got %+v, %v; want an error", name, findings, err)
		}
	}
}

// Reference model: an outflow is reported exactly when the holder is an
// existing contract, its balance is readable and positive, and net*100 > balance*percent.
func FuzzLargeOutflow(f *testing.F) {
	f.Add(uint64(600), uint64(0), uint64(1000), uint8(50), true, true)
	f.Add(uint64(500), uint64(0), uint64(1000), uint8(50), true, true)
	f.Add(uint64(10), uint64(20), uint64(5), uint8(1), true, true)
	f.Add(uint64(1), uint64(0), uint64(0), uint8(100), true, false)

	f.Fuzz(func(t *testing.T, out, in, balance uint64, percentByte uint8, isContract, measurable bool) {
		percent := int(percentByte)%100 + 1
		holder := vault
		if !isContract {
			holder = alice
		}
		bal := balances()
		if measurable {
			bal.balances[[2]common.Address{usdc, holder}] = new(big.Int).SetUint64(balance)
		}
		a := withFlows(nil, analysis.Flow{Asset: usdc, Holder: holder, Out: new(big.Int).SetUint64(out), In: new(big.Int).SetUint64(in)})

		found, err := mustDetector(t, bal, percent).Find(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}

		net := new(big.Int).Sub(new(big.Int).SetUint64(out), new(big.Int).SetUint64(in))
		b := new(big.Int).SetUint64(balance)
		want := isContract && measurable && net.Sign() > 0 && b.Sign() > 0 &&
			new(big.Int).Mul(net, big.NewInt(100)).Cmp(new(big.Int).Mul(b, big.NewInt(int64(percent)))) > 0
		if (len(found) == 1) != want || len(found) > 1 {
			t.Fatalf("found %+v, want reported=%v (net %s, balance %d, %d%%)", found, want, net, balance, percent)
		}
		if want && (found[0].Net.Cmp(net) != 0 || found[0].Balance.Cmp(b) != 0) {
			t.Fatalf("reported %+v, want net %s of %s", found[0], net, b)
		}
	})
}
