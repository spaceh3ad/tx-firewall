package rules

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
)

var (
	factory = common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	child   = common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")
	child2  = common.HexToAddress("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707")
)

func withFrames(frames ...analysis.Frame) *analysis.Analysis {
	a := txFrom(alice, &factory)
	a.Frames = frames
	return a
}

func frame(typ string, from, to common.Address, depth int) analysis.Frame {
	return analysis.Frame{Type: typ, From: from, To: to, Depth: depth}
}

func TestDeployAndCall(t *testing.T) {
	cases := map[string]struct {
		a         *analysis.Analysis
		wantAddrs []common.Address // empty: no finding
	}{
		"plain call": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CALL", factory, vault, 1),
		), nil},
		"deploy only": {withFrames(
			frame("CREATE", alice, child, 0),
		), nil},
		"factory deploys then calls": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE2", factory, child, 1),
			frame("CALL", factory, child, 1),
		), []common.Address{child}},
		"call from inside the constructor does not count": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE", factory, child, 1),
			frame("CALL", child, vault, 2),
			frame("CALL", vault, child, 3), // callback into a contract with no code yet
		), nil},
		"called deeper in the tree later": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE", factory, child, 1),
			frame("CALL", factory, vault, 1),
			frame("STATICCALL", vault, child, 2),
		), []common.Address{child}},
		"delegatecall into the new contract": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE", factory, child, 1),
			frame("DELEGATECALL", factory, child, 1),
		), []common.Address{child}},
		"call before the deploy does not count": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CALL", factory, child, 1),
			frame("CREATE2", factory, child, 1),
		), nil},
		"selfdestruct beneficiary is not a call": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE", factory, child, 1),
			frame("SELFDESTRUCT", vault, child, 1),
		), nil},
		"CREATE2 redeploy after selfdestruct is reported once": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE2", factory, child, 1),
			frame("CALL", factory, child, 1),
			frame("SELFDESTRUCT", child, factory, 2),
			frame("CREATE2", factory, child, 1),
			frame("CALL", factory, child, 1),
		), []common.Address{child}},
		"two contracts, each called twice": {withFrames(
			frame("CALL", alice, factory, 0),
			frame("CREATE", factory, child, 1),
			frame("CREATE", factory, child2, 1),
			frame("CALL", factory, child, 1),
			frame("CALL", factory, child2, 1),
			frame("CALL", factory, child, 1),
			frame("CALL", factory, child2, 1),
		), []common.Address{child, child2}},
	}
	rule := NewDeployAndCall()
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

// framesFrom builds a well-formed pre-order frame list from fuzz bytes. Each
// byte picks a type (bits 0-1), a target (bits 2-3) and whether to go one
// level deeper, stay, or return towards the root (bits 4-5). As on a real
// chain, an address is created at most once: a repeated CREATE becomes a CALL.
func framesFrom(data []byte) []analysis.Frame {
	types := []string{"CALL", "CREATE", "STATICCALL", "DELEGATECALL"}
	targets := []common.Address{vault, child, child2, factory}
	frames := []analysis.Frame{frame("CALL", alice, factory, 0)}
	created := map[common.Address]bool{}
	depth := 0
	for _, b := range data {
		typ, to := types[b&0x03], targets[(b>>2)&0x03]
		if typ == "CREATE" {
			if created[to] {
				typ = "CALL"
			}
			created[to] = true
		}
		switch (b >> 4) & 0x03 {
		case 0:
			depth++
		case 1:
			if depth > 1 {
				depth--
			}
		}
		depth = max(depth, 1)
		frames = append(frames, frame(typ, factory, to, depth))
	}
	return frames
}

// Reference model: fires exactly when some created contract is called after
// its constructor's subtree ends, and never reports the same address twice.
func FuzzDeployAndCall(f *testing.F) {
	f.Add([]byte{0x05, 0x14})       // create child, call child at the same depth
	f.Add([]byte{0x05, 0x04})       // create child, call child inside its constructor
	f.Add([]byte{0x14, 0x05, 0x14}) // call child, then create it
	f.Add([]byte{0x05, 0x19, 0x14, 0x18})

	f.Fuzz(func(t *testing.T, data []byte) {
		a := withFrames(framesFrom(data)...)

		wantFire := false
		for i, fr := range a.Frames {
			if !fr.IsCreate() {
				continue
			}
			for j := a.SubtreeEnd(i); j < len(a.Frames); j++ {
				if a.Frames[j].IsCall() && a.Frames[j].To == fr.To {
					wantFire = true
				}
			}
		}

		findings, err := NewDeployAndCall().Evaluate(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findings) == 1; got != wantFire || len(findings) > 1 {
			t.Fatalf("got %d findings, want fire=%v for %+v", len(findings), wantFire, a.Frames)
		}
		if wantFire {
			for _, addr := range []common.Address{vault, child, child2, factory} {
				if strings.Count(findings[0].Reason, addr.Hex()) > 1 {
					t.Fatalf("reason names %s more than once: %q", addr.Hex(), findings[0].Reason)
				}
			}
		}
	})
}
