// Package screen runs the screening pipeline for one transaction:
// build the analysis, then let the risk engine judge it.
package screen

import (
	"context"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/risk"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Screener screens decoded transactions.
type Screener struct {
	engine *risk.Engine
}

func New(engine *risk.Engine) *Screener {
	return &Screener{engine: engine}
}

// Screen judges the transaction from its decoded form alone; simulation comes later.
func (s *Screener) Screen(ctx context.Context, tx *txdecode.Decoded) (risk.Verdict, error) {
	return s.engine.Evaluate(ctx, analysis.FromTx(tx))
}
