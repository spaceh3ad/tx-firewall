// Package rules holds the screening rules. Each rule reads a prepared
// Analysis and reports findings; rules never query the node themselves,
// anything they need from the chain is passed in through their constructor.
package rules

import (
	"context"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
)

// Rule inspects one transaction.
type Rule interface {
	Name() string
	Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error)
}

// Finding is one reason a rule considers the transaction risky.
type Finding struct {
	Rule      string
	HardBlock bool   // blocks the transaction whatever the score
	Weight    int    // added to the risk score; never negative
	Reason    string // shown to the client, e.g. "sanctioned address 0xabc..."
}
