package analysis

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/events"
)

// ETH is the Asset of a Flow of native ether.
var ETH = common.Address{}

// Flow is how much of one asset an address sent and received in the transaction.
type Flow struct {
	Asset   common.Address // the ERC-20 token contract, or ETH
	Holder  common.Address
	Out, In *big.Int
}

// NetOut is what the holder ends up losing: sent minus received (negative if it gained).
func (f Flow) NetOut() *big.Int {
	return new(big.Int).Sub(f.Out, f.In)
}

// computeFlows sums ERC-20 transfers and ETH moved by frames per asset and
// holder, in order of first appearance. ETH moves with CALL, CREATE and
// CREATE2 values and with SELFDESTRUCT (the value is the balance swept to the
// beneficiary); DELEGATECALL, CALLCODE and STATICCALL frames report the
// caller's value but move nothing.
func computeFlows(frames []Frame, transfers []events.Transfer) []Flow {
	type key struct{ asset, holder common.Address }
	index := map[key]int{}
	var flows []Flow
	flow := func(asset, holder common.Address) *Flow {
		k := key{asset, holder}
		i, ok := index[k]
		if !ok {
			i = len(flows)
			index[k] = i
			flows = append(flows, Flow{Asset: asset, Holder: holder, Out: new(big.Int), In: new(big.Int)})
		}
		return &flows[i]
	}
	move := func(asset, from, to common.Address, amount *big.Int) {
		if from == to {
			return
		}
		out := flow(asset, from)
		out.Out.Add(out.Out, amount)
		in := flow(asset, to)
		in.In.Add(in.In, amount)
	}

	for _, f := range frames {
		switch f.Type {
		case "CALL", "CREATE", "CREATE2", "SELFDESTRUCT":
			if f.Value != nil {
				move(ETH, f.From, f.To, f.Value)
			}
		}
	}
	for _, t := range transfers {
		if t.Standard == events.ERC20 {
			move(t.Token, t.From, t.To, t.Amount)
		}
	}
	return flows
}
