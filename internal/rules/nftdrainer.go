package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
)

// NFTDrainer flags ApprovalForAll grants to an address without code (an
// EOA: marketplaces are contracts, so this is a classic phishing sign) or to
// a recently deployed contract. Revocations (approved = false) are ignored.
type NFTDrainer struct {
	status chainstate.StatusReader
}

var _ Rule = (*NFTDrainer)(nil)

func NewNFTDrainer(status chainstate.StatusReader) *NFTDrainer {
	return &NFTDrainer{status: status}
}

func (r *NFTDrainer) Name() string { return "nft-drainer" }

func (r *NFTDrainer) Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error) {
	kind := map[common.Address]string{} // operator -> "EOA", "recently deployed contract" or "" (established)
	var grants []string
	for _, ap := range a.ApprovalsForAll {
		if !ap.Approved {
			continue
		}
		k, known := kind[ap.Operator]
		if !known {
			var err error
			if k, err = r.operatorKind(ctx, a, ap.Operator); err != nil {
				return nil, err
			}
			kind[ap.Operator] = k
		}
		if k != "" {
			grants = append(grants, fmt.Sprintf("collection %s to %s %s", ap.Collection.Hex(), k, ap.Operator.Hex()))
		}
	}
	if len(grants) == 0 {
		return nil, nil
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightMedium,
		Reason: "approval for all NFTs: " + strings.Join(grants, ", "),
	}}, nil
}

// operatorKind describes a suspicious operator, or returns "" for an established contract.
func (r *NFTDrainer) operatorKind(ctx context.Context, a *analysis.Analysis, operator common.Address) (string, error) {
	if a.CreatedInTx(operator) {
		return "recently deployed contract", nil
	}
	s, err := r.status.Status(ctx, operator)
	if err != nil {
		return "", fmt.Errorf("status of %s: %w", operator.Hex(), err)
	}
	switch s {
	case chainstate.NoCode:
		return "EOA", nil
	case chainstate.Fresh:
		return "recently deployed contract", nil
	default:
		return "", nil
	}
}
