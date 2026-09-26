package rules

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/chainstate"
)

// Outflow is a contract losing a large share of an asset it held before the transaction.
type Outflow struct {
	Asset   common.Address // token contract, or analysis.ETH
	Holder  common.Address
	Net     *big.Int // sent minus received during the transaction
	Balance *big.Int // held before the transaction
}

func (o Outflow) String() string {
	asset := "token " + o.Asset.Hex()
	if o.Asset == analysis.ETH {
		asset = "ETH"
	}
	pct := new(big.Int).Div(new(big.Int).Mul(o.Net, big.NewInt(100)), o.Balance)
	return fmt.Sprintf("%s%% of %s held by %s (%s of %s)", pct, asset, o.Holder.Hex(), o.Net, o.Balance)
}

// OutflowDetector finds contracts whose net outflow of an asset is more than
// a percentage of what they held before the transaction. EOAs are ignored
// (people move their own funds), as are contracts created by the transaction
// and tokens whose balance can't be read.
type OutflowDetector struct {
	status   chainstate.StatusReader
	balances chainstate.BalanceReader
	percent  int64
}

func NewOutflowDetector(status chainstate.StatusReader, balances chainstate.BalanceReader, percent int) (*OutflowDetector, error) {
	if percent < 1 || percent > 100 {
		return nil, errors.New("large outflow percentage must be between 1 and 100")
	}
	return &OutflowDetector{status: status, balances: balances, percent: int64(percent)}, nil
}

func (d *OutflowDetector) Find(ctx context.Context, a *analysis.Analysis) ([]Outflow, error) {
	var found []Outflow
	for _, f := range a.Flows {
		net := f.NetOut()
		if net.Sign() <= 0 || f.Holder == (common.Address{}) || a.CreatedInTx(f.Holder) {
			continue
		}
		s, err := d.status.Status(ctx, f.Holder)
		if err != nil {
			return nil, fmt.Errorf("status of %s: %w", f.Holder.Hex(), err)
		}
		if s == chainstate.NoCode {
			continue
		}
		bal, ok, err := d.balances.Balance(ctx, f.Asset, f.Holder)
		if err != nil {
			return nil, err
		}
		if !ok || bal.Sign() == 0 {
			continue
		}
		// net/bal > percent/100, in integers.
		if new(big.Int).Mul(net, big.NewInt(100)).Cmp(new(big.Int).Mul(bal, big.NewInt(d.percent))) > 0 {
			found = append(found, Outflow{Asset: f.Asset, Holder: f.Holder, Net: net, Balance: bal})
		}
	}
	return found, nil
}

// LargeOutflow flags a contract losing more than the configured share of an
// asset in one transaction, the signature of a drained vault or pool.
type LargeOutflow struct {
	detector *OutflowDetector
}

var _ Rule = (*LargeOutflow)(nil)

func NewLargeOutflow(detector *OutflowDetector) *LargeOutflow {
	return &LargeOutflow{detector: detector}
}

func (r *LargeOutflow) Name() string { return "large-outflow" }

func (r *LargeOutflow) Evaluate(ctx context.Context, a *analysis.Analysis) ([]Finding, error) {
	outflows, err := r.detector.Find(ctx, a)
	if err != nil || len(outflows) == 0 {
		return nil, err
	}
	parts := make([]string, len(outflows))
	for i, o := range outflows {
		parts[i] = o.String()
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightHigh,
		Reason: "large outflow: " + strings.Join(parts, ", "),
	}}, nil
}
