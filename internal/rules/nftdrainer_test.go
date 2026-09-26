package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
	"github.com/spaceh3ad/tx-firewall/internal/events"
)

var (
	bayc        = common.HexToAddress("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D")
	marketplace = common.HexToAddress("0x1E0049783F008A0085193E00003D00cd54003c71") // established
	phisher     = common.HexToAddress("0x000000000000000000000000000000000000bAd1") // EOA
)

// fakeStatus answers from a fixed map (default NoCode) and counts lookups.
type fakeStatus struct {
	status map[common.Address]chainstate.Status
	err    error
	calls  map[common.Address]int
}

func newFakeStatus(status map[common.Address]chainstate.Status) *fakeStatus {
	return &fakeStatus{status: status, calls: map[common.Address]int{}}
}

func (f *fakeStatus) Status(_ context.Context, addr common.Address) (chainstate.Status, error) {
	f.calls[addr]++
	return f.status[addr], f.err
}

func withApprovalsForAll(created []common.Address, aps ...events.ApprovalForAll) *analysis.Analysis {
	a := txFrom(alice, &bayc)
	a.Created = created
	a.ApprovalsForAll = aps
	return a
}

func approvalForAll(operator common.Address, approved bool) events.ApprovalForAll {
	return events.ApprovalForAll{Collection: bayc, Owner: alice, Operator: operator, Approved: approved}
}

func TestNFTDrainer(t *testing.T) {
	status := map[common.Address]chainstate.Status{
		marketplace: chainstate.Established,
		drainer:     chainstate.Fresh,
		// phisher: no entry, so NoCode
	}
	cases := map[string]struct {
		a    *analysis.Analysis
		want []string // substrings; empty: no finding
	}{
		"approval to established marketplace": {withApprovalsForAll(nil, approvalForAll(marketplace, true)), nil},
		"approval to an EOA":                  {withApprovalsForAll(nil, approvalForAll(phisher, true)), []string{"EOA " + phisher.Hex(), bayc.Hex()}},
		"approval to fresh contract":          {withApprovalsForAll(nil, approvalForAll(drainer, true)), []string{"recently deployed contract " + drainer.Hex()}},
		"approval to contract created in tx":  {withApprovalsForAll([]common.Address{child}, approvalForAll(child, true)), []string{"recently deployed contract " + child.Hex()}},
		"revocation from an EOA":              {withApprovalsForAll(nil, approvalForAll(phisher, false)), nil},
		"no approvals":                        {withApprovalsForAll(nil), nil},
	}
	rule := NewNFTDrainer(newFakeStatus(status))
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
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
			if f.Weight != WeightMedium || f.HardBlock || f.Rule != rule.Name() {
				t.Errorf("finding = %+v, want a medium-weight %s finding", f, rule.Name())
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Reason, want) {
					t.Errorf("reason %q does not contain %q", f.Reason, want)
				}
			}
		})
	}
}

func TestNFTDrainerLookups(t *testing.T) {
	status := newFakeStatus(map[common.Address]chainstate.Status{marketplace: chainstate.Established})
	a := withApprovalsForAll([]common.Address{child},
		approvalForAll(phisher, true),
		approvalForAll(phisher, true),
		approvalForAll(child, true),
		approvalForAll(marketplace, false), // revocation: no lookup
	)
	if _, err := NewNFTDrainer(status).Evaluate(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if status.calls[phisher] != 1 || status.calls[child] != 0 || status.calls[marketplace] != 0 {
		t.Errorf("lookups = %v, want phisher once and nothing else", status.calls)
	}
}

func TestNFTDrainerPropagatesErrors(t *testing.T) {
	status := newFakeStatus(nil)
	status.err = errors.New("node unavailable")
	findings, err := NewNFTDrainer(status).Evaluate(t.Context(), withApprovalsForAll(nil, approvalForAll(marketplace, true)))
	if err == nil || findings != nil {
		t.Errorf("got findings %+v, err %v; want no findings and an error", findings, err)
	}
}

// Reference model: fires exactly when some granted (not revoked) approval
// goes to an operator that has no code, is fresh, or was created in the transaction.
func FuzzNFTDrainer(f *testing.F) {
	f.Add([]byte{0x04}, uint8(0x00), uint8(0))
	f.Add([]byte{0x05}, uint8(0x11), uint8(0))
	f.Add([]byte{0x01}, uint8(0x55), uint8(0x01))

	operators := []common.Address{marketplace, phisher, drainer, child}

	f.Fuzz(func(t *testing.T, data []byte, statusBits, createdMask uint8) {
		status := map[common.Address]chainstate.Status{}
		var created []common.Address
		for i, op := range operators {
			status[op] = chainstate.Status((statusBits >> (2 * i)) & 0x03 % 3)
			if createdMask&(1<<i) != 0 {
				created = append(created, op)
			}
		}
		var aps []events.ApprovalForAll
		wantFire := false
		for _, b := range data {
			i, approved := int(b&0x03), b&0x04 != 0
			aps = append(aps, approvalForAll(operators[i], approved))
			suspicious := createdMask&(1<<i) != 0 || status[operators[i]] != chainstate.Established
			if approved && suspicious {
				wantFire = true
			}
		}

		findings, err := NewNFTDrainer(newFakeStatus(status)).Evaluate(t.Context(), withApprovalsForAll(created, aps...))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findings) == 1; got != wantFire || len(findings) > 1 {
			t.Fatalf("got %d findings, want fire=%v", len(findings), wantFire)
		}
	})
}
