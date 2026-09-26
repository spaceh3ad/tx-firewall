package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
)

var (
	proxy   = common.HexToAddress("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0")
	oldImpl = common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	newImpl = common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")
)

// fakeFreshness answers from a fixed set and counts lookups per address.
type fakeFreshness struct {
	fresh map[common.Address]bool
	err   error
	calls map[common.Address]int
}

func newFakeFreshness(fresh ...common.Address) *fakeFreshness {
	f := &fakeFreshness{fresh: map[common.Address]bool{}, calls: map[common.Address]int{}}
	for _, a := range fresh {
		f.fresh[a] = true
	}
	return f
}

func (f *fakeFreshness) IsFreshContract(_ context.Context, addr common.Address) (bool, error) {
	f.calls[addr]++
	return f.fresh[addr], f.err
}

func TestDelegatecallToFresh(t *testing.T) {
	cases := map[string]struct {
		a         *analysis.Analysis
		wantAddrs []common.Address
	}{
		"proxy to established implementation": {withFrames(
			frame("CALL", alice, proxy, 0),
			frame("DELEGATECALL", proxy, oldImpl, 1),
		), nil},
		"proxy to fresh implementation": {withFrames(
			frame("CALL", alice, proxy, 0),
			frame("DELEGATECALL", proxy, newImpl, 1),
		), []common.Address{newImpl}},
		"CALLCODE to fresh code": {withFrames(
			frame("CALL", alice, proxy, 0),
			frame("CALLCODE", proxy, newImpl, 1),
		), []common.Address{newImpl}},
		"plain call to fresh contract is not a delegatecall": {withFrames(
			frame("CALL", alice, proxy, 0),
			frame("CALL", proxy, newImpl, 1),
		), nil},
		"same fresh target twice is reported once": {withFrames(
			frame("CALL", alice, proxy, 0),
			frame("DELEGATECALL", proxy, newImpl, 1),
			frame("DELEGATECALL", proxy, newImpl, 1),
		), []common.Address{newImpl}},
	}
	rule := NewDelegatecallToFresh(newFakeFreshness(newImpl))
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := rule.Evaluate(t.Context(), tc.a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tc.wantAddrs) == 0 {
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
			for _, addr := range tc.wantAddrs {
				if strings.Count(f.Reason, addr.Hex()) != 1 {
					t.Errorf("reason %q should name %s exactly once", f.Reason, addr.Hex())
				}
			}
		})
	}
}

func TestDelegatecallToFreshCreatedInTx(t *testing.T) {
	fresh := newFakeFreshness() // the node knows nothing about the new contract yet
	a := withFrames(
		frame("CALL", alice, factory, 0),
		frame("CREATE", factory, child, 1),
		frame("DELEGATECALL", factory, child, 1),
	)
	a.Created = []common.Address{child}

	findings, err := NewDelegatecallToFresh(fresh).Evaluate(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Reason, child.Hex()) {
		t.Errorf("findings = %+v, want one naming %s", findings, child.Hex())
	}
	if fresh.calls[child] != 0 {
		t.Error("asked the node about a contract created in this transaction")
	}
}

func TestDelegatecallToFreshLooksUpEachTargetOnce(t *testing.T) {
	fresh := newFakeFreshness()
	a := withFrames(
		frame("CALL", alice, proxy, 0),
		frame("DELEGATECALL", proxy, oldImpl, 1),
		frame("CALL", proxy, vault, 1),
		frame("DELEGATECALL", vault, oldImpl, 2),
	)
	if _, err := NewDelegatecallToFresh(fresh).Evaluate(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if fresh.calls[oldImpl] != 1 {
		t.Errorf("looked up %s %d times, want 1", oldImpl.Hex(), fresh.calls[oldImpl])
	}
}

func TestDelegatecallToFreshPropagatesErrors(t *testing.T) {
	fresh := newFakeFreshness()
	fresh.err = errors.New("missing trie node")
	a := withFrames(frame("CALL", alice, proxy, 0), frame("DELEGATECALL", proxy, oldImpl, 1))

	findings, err := NewDelegatecallToFresh(fresh).Evaluate(t.Context(), a)
	if err == nil || findings != nil {
		t.Errorf("got findings %+v, err %v; want no findings and an error", findings, err)
	}
}

// Reference model: fires exactly when a DELEGATECALL or CALLCODE targets a
// fresh contract or one created in the transaction, and asks the node at most
// once per target and never about contracts created in the transaction.
func FuzzDelegatecallToFresh(f *testing.F) {
	f.Add([]byte{0x03, 0x07}, uint8(0x02), uint8(0))
	f.Add([]byte{0x03}, uint8(0), uint8(0x02))
	f.Add([]byte{0x00, 0x04, 0x08}, uint8(0x0f), uint8(0))

	targets := []common.Address{vault, child, child2, factory}
	types := []string{"CALL", "STATICCALL", "CALLCODE", "DELEGATECALL"}

	f.Fuzz(func(t *testing.T, data []byte, freshMask, createdMask uint8) {
		var freshAddrs, created []common.Address
		for i, addr := range targets {
			if freshMask&(1<<i) != 0 {
				freshAddrs = append(freshAddrs, addr)
			}
			if createdMask&(1<<i) != 0 {
				created = append(created, addr)
			}
		}
		frames := []analysis.Frame{frame("CALL", alice, proxy, 0)}
		wantFire := false
		for _, b := range data {
			fr := frame(types[b&0x03], proxy, targets[(b>>2)&0x03], 1)
			frames = append(frames, fr)
			if (fr.Type == "DELEGATECALL" || fr.Type == "CALLCODE") &&
				(freshMask&(1<<((b>>2)&0x03)) != 0 || createdMask&(1<<((b>>2)&0x03)) != 0) {
				wantFire = true
			}
		}
		a := withFrames(frames...)
		a.Created = created
		fresh := newFakeFreshness(freshAddrs...)

		findings, err := NewDelegatecallToFresh(fresh).Evaluate(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findings) == 1; got != wantFire || len(findings) > 1 {
			t.Fatalf("got %d findings, want fire=%v", len(findings), wantFire)
		}
		for i, addr := range targets {
			if fresh.calls[addr] > 1 {
				t.Fatalf("looked up %s %d times", addr.Hex(), fresh.calls[addr])
			}
			if createdMask&(1<<i) != 0 && fresh.calls[addr] != 0 {
				t.Fatalf("asked the node about %s, created in this transaction", addr.Hex())
			}
		}
	})
}
