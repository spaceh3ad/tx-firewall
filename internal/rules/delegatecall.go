package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
)

// DelegatecallToFresh flags DELEGATECALL (and CALLCODE) into recently deployed
// code: that code runs with the caller's storage and balance, so a new,
// unaudited target can take over the calling contract.
type DelegatecallToFresh struct {
	fresh chainstate.FreshnessChecker
}

var _ Rule = (*DelegatecallToFresh)(nil)

func NewDelegatecallToFresh(fresh chainstate.FreshnessChecker) *DelegatecallToFresh {
	return &DelegatecallToFresh{fresh: fresh}
}

func (r *DelegatecallToFresh) Name() string { return "delegatecall-to-fresh-code" }

func (r *DelegatecallToFresh) Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error) {
	checked := map[common.Address]bool{}
	var targets []string
	for _, f := range a.Frames {
		if (f.Type != "DELEGATECALL" && f.Type != "CALLCODE") || checked[f.To] {
			continue
		}
		checked[f.To] = true

		// Deployed by this transaction: fresh by definition, no need to ask the node.
		fresh := a.CreatedInTx(f.To)
		if !fresh {
			var err error
			if fresh, err = r.fresh.IsFreshContract(ctx, f.To); err != nil {
				return nil, fmt.Errorf("freshness of %s: %w", f.To.Hex(), err)
			}
		}
		if fresh {
			targets = append(targets, f.To.Hex())
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightMedium,
		Reason: "delegatecall into recently deployed code: " + strings.Join(targets, ", "),
	}}, nil
}
