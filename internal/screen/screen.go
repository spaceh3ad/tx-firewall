// Package screen runs the screening pipeline for one transaction:
// simulate it, build the analysis, then let the risk engine judge it.
package screen

import (
	"context"
	"errors"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/rules"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Screener screens decoded transactions.
type Screener struct {
	sim    simulate.Simulator
	engine *risk.Engine
}

func New(sim simulate.Simulator, engine *risk.Engine) *Screener {
	return &Screener{sim: sim, engine: engine}
}

// Screen simulates the transaction and evaluates the rules on the result.
// If the node refuses to execute the transaction, it is blocked with the
// node's reason; any other simulation failure is returned as an error.
func (s *Screener) Screen(ctx context.Context, tx *txdecode.Decoded) (risk.Verdict, error) {
	trace, err := s.sim.Simulate(ctx, tx)
	var nodeErr *simulate.NodeError
	if errors.As(err, &nodeErr) {
		return risk.Verdict{
			Block: true,
			Findings: []rules.Finding{{
				Rule:      "simulation",
				HardBlock: true,
				Reason:    "simulation failed: " + nodeErr.Message,
			}},
		}, nil
	}
	if err != nil {
		return risk.Verdict{}, err
	}
	return s.engine.Evaluate(ctx, analysis.Build(tx, trace))
}
