package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
)

// FlashLoanOutflow flags a flash loan combined with a large outflow from a
// contract other than the lender: borrowed capital used to drain someone
// else, the shape of most price-manipulation and governance exploits. The
// lender itself is excluded because lending and being repaid moves its funds
// by design. It adds to the large-outflow rule, so together they block.
type FlashLoanOutflow struct {
	detector *OutflowDetector
}

var _ Rule = (*FlashLoanOutflow)(nil)

func NewFlashLoanOutflow(detector *OutflowDetector) *FlashLoanOutflow {
	return &FlashLoanOutflow{detector: detector}
}

func (r *FlashLoanOutflow) Name() string { return "flash-loan-outflow" }

func (r *FlashLoanOutflow) Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error) {
	if len(a.FlashLoans) == 0 {
		return nil, nil // balance lookups only when there is a loan
	}
	outflows, err := r.detector.Find(ctx, a)
	if err != nil {
		return nil, err
	}

	lenders := map[common.Address]bool{}
	loans := make([]string, 0, len(a.FlashLoans))
	for _, l := range a.FlashLoans {
		lenders[l.Lender] = true
		loans = append(loans, fmt.Sprintf("%s (%s)", l.Lender.Hex(), l.Source))
	}
	var drained []string
	for _, o := range outflows {
		if !lenders[o.Holder] {
			drained = append(drained, o.String())
		}
	}
	if len(drained) == 0 {
		return nil, nil
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightHigh,
		Reason: "flash loan from " + strings.Join(loans, ", ") + " with large outflow: " + strings.Join(drained, ", "),
	}}, nil
}
