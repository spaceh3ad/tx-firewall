package rules

import (
	"context"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
)

// DeployAndCall flags transactions that deploy a contract and then call it,
// the usual shape of an exploit contract created and fired in one go.
// Calls made while the contract is still being constructed don't count: its
// code isn't deployed until the constructor returns. Factories that deploy
// and initialise in one transaction also match, hence the medium weight.
type DeployAndCall struct{}

var _ Rule = DeployAndCall{}

func NewDeployAndCall() DeployAndCall { return DeployAndCall{} }

func (DeployAndCall) Name() string { return "deploy-and-call" }

func (r DeployAndCall) Evaluate(_ context.Context, a *analysis.Analysis) ([]Finding, error) {
	// deployedAt maps each created contract to the index where its first
	// constructor finished; from there on the contract has code.
	deployedAt := map[common.Address]int{}
	reported := map[common.Address]bool{}
	var called []string
	for i, f := range a.Frames {
		if f.IsCreate() {
			if _, seen := deployedAt[f.To]; !seen {
				deployedAt[f.To] = a.SubtreeEnd(i)
			}
			continue
		}
		end, created := deployedAt[f.To]
		// reported is separate from deployedAt because CREATE2 can redeploy the
		// same address after a selfdestruct within one transaction.
		if f.IsCall() && created && i >= end && !reported[f.To] {
			called = append(called, f.To.Hex())
			reported[f.To] = true
		}
	}
	if len(called) == 0 {
		return nil, nil
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightMedium,
		Reason: "contract deployed and called in the same transaction: " + strings.Join(called, ", "),
	}}, nil
}
