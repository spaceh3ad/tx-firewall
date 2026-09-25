package rules

import (
	"context"
	"fmt"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/sanctions"
)

// Sanctioned hard-blocks any transaction that touches a sanctioned address.
type Sanctioned struct {
	checker sanctions.Checker
}

var _ Rule = (*Sanctioned)(nil)

func NewSanctioned(checker sanctions.Checker) *Sanctioned {
	return &Sanctioned{checker: checker}
}

func (r *Sanctioned) Name() string { return "sanctioned-address" }

// Evaluate returns one finding per sanctioned address. A failed lookup is an
// error, never a pass: the caller decides how to handle an incomplete check.
func (r *Sanctioned) Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error) {
	var findings []Finding
	for _, addr := range a.Addresses {
		hit, err := r.checker.IsSanctioned(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("check %s: %w", addr.Hex(), err)
		}
		if hit {
			findings = append(findings, Finding{
				Rule:      r.Name(),
				HardBlock: true,
				Reason:    "sanctioned address " + addr.Hex(),
			})
		}
	}
	return findings, nil
}
