package rules

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
)

// UnlimitedAmount is the smallest ERC-20 approval treated as unlimited. It
// covers type(uint256).max and the other "max" values wallets use (uint160,
// uint128), and sits far above any real balance.
var UnlimitedAmount = new(big.Int).Lsh(big.NewInt(1), 128)

// UnlimitedApproval flags unlimited ERC-20 approvals to recently deployed
// contracts, the classic setup for draining a wallet later.
type UnlimitedApproval struct {
	fresh chainstate.FreshnessChecker
}

var _ Rule = (*UnlimitedApproval)(nil)

func NewUnlimitedApproval(fresh chainstate.FreshnessChecker) *UnlimitedApproval {
	return &UnlimitedApproval{fresh: fresh}
}

func (r *UnlimitedApproval) Name() string { return "unlimited-approval-to-fresh-contract" }

func (r *UnlimitedApproval) Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error) {
	checked := map[common.Address]bool{}
	var approvals []string
	for _, ap := range a.Approvals {
		if ap.Amount.Cmp(UnlimitedAmount) < 0 {
			continue
		}
		fresh, known := checked[ap.Spender]
		if !known {
			var err error
			if fresh, err = isFresh(ctx, r.fresh, a, ap.Spender); err != nil {
				return nil, err
			}
			checked[ap.Spender] = fresh
		}
		if fresh {
			approvals = append(approvals, fmt.Sprintf("token %s to %s", ap.Token.Hex(), ap.Spender.Hex()))
		}
	}
	if len(approvals) == 0 {
		return nil, nil
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightMedium,
		Reason: "unlimited approval to recently deployed contract: " + strings.Join(approvals, ", "),
	}}, nil
}

// isFresh treats contracts created by the transaction as fresh without asking the node.
func isFresh(ctx context.Context, fresh chainstate.FreshnessChecker, a *analysis.Analysis, addr common.Address) (bool, error) {
	if a.CreatedInTx(addr) {
		return true, nil
	}
	ok, err := fresh.IsFreshContract(ctx, addr)
	if err != nil {
		return false, fmt.Errorf("freshness of %s: %w", addr.Hex(), err)
	}
	return ok, nil
}
