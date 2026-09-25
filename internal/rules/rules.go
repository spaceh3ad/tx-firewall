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

// Weights of the README's risk levels. With the default threshold of 50,
// one high-weight finding flags a transaction but takes a second signal to block.
const (
	WeightHigh   = 40
	WeightMedium = 20
)

// Finding is one reason a rule considers the transaction risky.
// A weighted rule reports at most one finding per transaction, so its weight
// counts once however many times the pattern occurs.
type Finding struct {
	Rule      string
	HardBlock bool   // blocks the transaction whatever the score
	Weight    int    // added to the risk score; never negative
	Reason    string // shown to the client, e.g. "sanctioned address 0xabc..."
}
