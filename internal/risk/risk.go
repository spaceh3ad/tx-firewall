// Package risk runs the rules and turns their findings into a verdict.
package risk

import (
	"context"
	"errors"
	"fmt"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
)

// Verdict is the outcome of screening one transaction.
type Verdict struct {
	Block    bool
	Score    int
	Findings []rules.Finding
}

// Engine blocks a transaction when any finding is a hard block,
// or when the summed weights reach the threshold.
type Engine struct {
	rules     []rules.Rule
	threshold int
}

// NewEngine requires a positive threshold: with zero, every transaction would block.
func NewEngine(threshold int, rs ...rules.Rule) (*Engine, error) {
	if threshold <= 0 {
		return nil, errors.New("risk threshold must be positive")
	}
	return &Engine{rules: rs, threshold: threshold}, nil
}

// Evaluate runs every rule. If any rule fails the whole evaluation fails:
// a partial verdict could let a risky transaction through.
func (e *Engine) Evaluate(ctx context.Context, a *analysis.Analysis) (Verdict, error) {
	var v Verdict
	for _, r := range e.rules {
		findings, err := r.Evaluate(ctx, a)
		if err != nil {
			return Verdict{}, fmt.Errorf("rule %s: %w", r.Name(), err)
		}
		for _, f := range findings {
			v.Findings = append(v.Findings, f)
			v.Score += f.Weight
			if f.HardBlock {
				v.Block = true
			}
		}
	}
	if v.Score >= e.threshold {
		v.Block = true
	}
	return v, nil
}
