package risk

import (
	"context"
	"errors"
	"testing"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
)

// fixedRule returns the same findings (or error) for every transaction.
type fixedRule struct {
	name     string
	findings []rules.Finding
	err      error
}

func (r fixedRule) Name() string { return r.name }

func (r fixedRule) Evaluate(context.Context, *analysis.Analysis) ([]rules.Finding, error) {
	return r.findings, r.err
}

func weighted(w int) rules.Finding { return rules.Finding{Rule: "weighted", Weight: w} }

var hardBlock = rules.Finding{Rule: "hard", HardBlock: true}

func mustEngine(t *testing.T, threshold int, rs ...rules.Rule) *Engine {
	t.Helper()
	e, err := NewEngine(threshold, rs...)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestNewEngineRejectsNonPositiveThreshold(t *testing.T) {
	for _, threshold := range []int{0, -1} {
		if _, err := NewEngine(threshold); err == nil {
			t.Errorf("threshold %d: expected an error", threshold)
		}
	}
}

func TestEvaluate(t *testing.T) {
	cases := map[string]struct {
		rules     []rules.Rule
		wantBlock bool
		wantScore int
	}{
		"no rules":        {nil, false, 0},
		"no findings":     {[]rules.Rule{fixedRule{name: "a"}}, false, 0},
		"below threshold": {[]rules.Rule{fixedRule{name: "a", findings: []rules.Finding{weighted(25), weighted(24)}}}, false, 49},
		"at threshold":    {[]rules.Rule{fixedRule{name: "a", findings: []rules.Finding{weighted(25), weighted(25)}}}, true, 50},
		"summed across rules": {[]rules.Rule{
			fixedRule{name: "a", findings: []rules.Finding{weighted(25)}},
			fixedRule{name: "b", findings: []rules.Finding{weighted(30)}},
		}, true, 55},
		"hard block with zero score": {[]rules.Rule{fixedRule{name: "a", findings: []rules.Finding{hardBlock}}}, true, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := mustEngine(t, 50, tc.rules...).Evaluate(t.Context(), &analysis.Analysis{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.Block != tc.wantBlock || v.Score != tc.wantScore {
				t.Errorf("verdict = block %v score %d, want block %v score %d", v.Block, v.Score, tc.wantBlock, tc.wantScore)
			}
		})
	}
}

func TestEvaluateKeepsFindingsInRuleOrder(t *testing.T) {
	a := rules.Finding{Rule: "a", Weight: 1}
	b := rules.Finding{Rule: "b", Weight: 2}
	c := rules.Finding{Rule: "c", HardBlock: true}

	v, err := mustEngine(t, 50,
		fixedRule{name: "first", findings: []rules.Finding{a, b}},
		fixedRule{name: "second", findings: []rules.Finding{c}},
	).Evaluate(t.Context(), &analysis.Analysis{})
	if err != nil {
		t.Fatal(err)
	}
	want := []rules.Finding{a, b, c}
	if len(v.Findings) != len(want) {
		t.Fatalf("findings = %+v, want %+v", v.Findings, want)
	}
	for i := range want {
		if v.Findings[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, v.Findings[i], want[i])
		}
	}
}

func TestEvaluateFailsWhenAnyRuleFails(t *testing.T) {
	boom := errors.New("node unavailable")
	e := mustEngine(t, 50,
		fixedRule{name: "ok", findings: []rules.Finding{weighted(10)}},
		fixedRule{name: "broken", err: boom},
	)

	v, err := e.Evaluate(t.Context(), &analysis.Analysis{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
	if v.Block || v.Score != 0 || v.Findings != nil {
		t.Errorf("verdict must be empty on error, got %+v", v)
	}
}

// findingsFrom turns fuzz bytes into findings: the high bit marks a hard block,
// the low 7 bits are the weight, so weights are never negative.
func findingsFrom(data []byte) []rules.Finding {
	fs := make([]rules.Finding, len(data))
	for i, b := range data {
		fs[i] = rules.Finding{Rule: "fuzz", HardBlock: b&0x80 != 0, Weight: int(b & 0x7f)}
	}
	return fs
}

// Invariants of the verdict, for any set of findings and threshold:
//   - Score is the sum of the weights.
//   - Block is true exactly when a finding is a hard block or the score reaches the threshold.
//   - Adding another finding can never turn a block into an allow.
func FuzzEvaluateInvariants(f *testing.F) {
	f.Add([]byte{}, byte(0), uint8(49))
	f.Add([]byte{25, 25}, byte(0), uint8(49))
	f.Add([]byte{0x80}, byte(10), uint8(0))
	f.Add([]byte{10, 20, 0x85}, byte(0x80), uint8(200))

	f.Fuzz(func(t *testing.T, data []byte, extra byte, thresholdByte uint8) {
		threshold := int(thresholdByte) + 1
		findings := findingsFrom(data)

		v, err := mustEngine(t, threshold, fixedRule{name: "fuzz", findings: findings}).
			Evaluate(t.Context(), &analysis.Analysis{})
		if err != nil {
			t.Fatal(err)
		}

		sum, hard := 0, false
		for _, f := range findings {
			sum += f.Weight
			hard = hard || f.HardBlock
		}
		if v.Score != sum {
			t.Fatalf("score = %d, want %d", v.Score, sum)
		}
		if want := hard || sum >= threshold; v.Block != want {
			t.Fatalf("block = %v, want %v (hard=%v sum=%d threshold=%d)", v.Block, want, hard, sum, threshold)
		}
		if len(v.Findings) != len(findings) {
			t.Fatalf("got %d findings, want %d", len(v.Findings), len(findings))
		}

		more, err := mustEngine(t, threshold,
			fixedRule{name: "fuzz", findings: findings},
			fixedRule{name: "extra", findings: findingsFrom([]byte{extra})},
		).Evaluate(t.Context(), &analysis.Analysis{})
		if err != nil {
			t.Fatal(err)
		}
		if v.Block && !more.Block {
			t.Fatal("adding a finding turned a block into an allow")
		}
	})
}
