package rules

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/events"
)

var (
	usdc    = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	dai     = common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F")
	router  = common.HexToAddress("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45") // established
	drainer = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
)

func withApprovals(created []common.Address, aps ...events.Approval) *analysis.Analysis {
	a := txFrom(alice, &usdc)
	a.Created = created
	a.Approvals = aps
	return a
}

func approval(token, spender common.Address, amount *big.Int) events.Approval {
	return events.Approval{Token: token, Owner: alice, Spender: spender, Amount: amount}
}

func TestUnlimitedApproval(t *testing.T) {
	maxUint160 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	justBelow := new(big.Int).Sub(UnlimitedAmount, big.NewInt(1))

	cases := map[string]struct {
		a        *analysis.Analysis
		wantPair []string // substrings; empty: no finding
	}{
		"max approval to established router": {withApprovals(nil, approval(usdc, router, math.MaxBig256)), nil},
		"max approval to fresh contract":     {withApprovals(nil, approval(usdc, drainer, math.MaxBig256)), []string{"token " + usdc.Hex() + " to " + drainer.Hex()}},
		"uint160 max counts as unlimited":    {withApprovals(nil, approval(usdc, drainer, maxUint160)), []string{drainer.Hex()}},
		"exactly 2^128 counts":               {withApprovals(nil, approval(usdc, drainer, UnlimitedAmount)), []string{drainer.Hex()}},
		"just below 2^128 does not":          {withApprovals(nil, approval(usdc, drainer, justBelow)), nil},
		"limited approval to fresh contract": {withApprovals(nil, approval(usdc, drainer, big.NewInt(1_000_000))), nil},
		"revocation":                         {withApprovals(nil, approval(usdc, drainer, big.NewInt(0))), nil},
		"spender created in this tx":         {withApprovals([]common.Address{child}, approval(usdc, child, math.MaxBig256)), []string{child.Hex()}},
		"two tokens to the same drainer": {withApprovals(nil,
			approval(usdc, drainer, math.MaxBig256),
			approval(dai, drainer, math.MaxBig256),
		), []string{usdc.Hex(), dai.Hex()}},
	}
	rule := NewUnlimitedApproval(newFakeFreshness(drainer))
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := rule.Evaluate(t.Context(), tc.a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tc.wantPair) == 0 {
				if len(findings) != 0 {
					t.Errorf("unexpected findings: %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Weight != WeightMedium || f.HardBlock || f.Rule != rule.Name() {
				t.Errorf("finding = %+v, want a medium-weight %s finding", f, rule.Name())
			}
			for _, want := range tc.wantPair {
				if !strings.Contains(f.Reason, want) {
					t.Errorf("reason %q does not contain %q", f.Reason, want)
				}
			}
		})
	}
}

func TestUnlimitedApprovalLookups(t *testing.T) {
	fresh := newFakeFreshness(drainer)
	a := withApprovals([]common.Address{child},
		approval(usdc, drainer, math.MaxBig256),
		approval(dai, drainer, math.MaxBig256),
		approval(usdc, child, math.MaxBig256),
		approval(usdc, router, big.NewInt(5)), // limited: no lookup needed
	)
	if _, err := NewUnlimitedApproval(fresh).Evaluate(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if fresh.calls[drainer] != 1 || fresh.calls[child] != 0 || fresh.calls[router] != 0 {
		t.Errorf("lookups = %v, want drainer once and nothing else", fresh.calls)
	}
}

func TestUnlimitedApprovalPropagatesErrors(t *testing.T) {
	fresh := newFakeFreshness()
	fresh.err = errors.New("node unavailable")
	findings, err := NewUnlimitedApproval(fresh).Evaluate(t.Context(), withApprovals(nil, approval(usdc, router, math.MaxBig256)))
	if err == nil || findings != nil {
		t.Errorf("got findings %+v, err %v; want no findings and an error", findings, err)
	}
}

// Reference model: fires exactly when some approval of at least 2^128 goes to
// a fresh spender or one created in the transaction.
func FuzzUnlimitedApproval(f *testing.F) {
	f.Add([]byte{0x80, 0x01}, uint8(0x02), uint8(0))
	f.Add([]byte{0x7f}, uint8(0xff), uint8(0))
	f.Add([]byte{0x81}, uint8(0), uint8(0x02))

	spenders := []common.Address{router, drainer, child, child2}

	f.Fuzz(func(t *testing.T, data []byte, freshMask, createdMask uint8) {
		var freshAddrs, created []common.Address
		for i, s := range spenders {
			if freshMask&(1<<i) != 0 {
				freshAddrs = append(freshAddrs, s)
			}
			if createdMask&(1<<i) != 0 {
				created = append(created, s)
			}
		}
		var aps []events.Approval
		wantFire := false
		for _, b := range data {
			// bit 7: unlimited or not; low bits: spender; the amount straddles 2^128.
			amount := new(big.Int).Sub(UnlimitedAmount, big.NewInt(int64(b&0x70)))
			if b&0x80 != 0 {
				amount = new(big.Int).Add(UnlimitedAmount, big.NewInt(int64(b&0x70)))
			}
			i := int(b & 0x03)
			aps = append(aps, approval(usdc, spenders[i], amount))
			if amount.Cmp(UnlimitedAmount) >= 0 && (freshMask&(1<<i) != 0 || createdMask&(1<<i) != 0) {
				wantFire = true
			}
		}

		findings, err := NewUnlimitedApproval(newFakeFreshness(freshAddrs...)).Evaluate(t.Context(), withApprovals(created, aps...))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findings) == 1; got != wantFire || len(findings) > 1 {
			t.Fatalf("got %d findings, want fire=%v", len(findings), wantFire)
		}
	})
}
