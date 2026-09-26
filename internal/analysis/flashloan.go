package analysis

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/events"
)

// RepaidPattern is the FlashLoan Source of loans found from transfers rather than a protocol event.
const RepaidPattern = "borrow-and-repay pattern"

// FlashLoan is a loan borrowed and repaid within the transaction.
type FlashLoan struct {
	Lender common.Address
	Token  common.Address // zero when unknown
	Amount *big.Int       // nil when unknown
	Source string         // the protocol that announced it, or RepaidPattern
}

// findRepaidLoans spots the generic shape of a flash loan in ERC-20 transfers
// (in execution order): a token leaves an address, and later at least the
// same amount of it comes back. Each lender and token pair is reported once.
func findRepaidLoans(transfers []events.Transfer) []FlashLoan {
	type key struct{ lender, token common.Address }
	seen := map[key]bool{}
	var loans []FlashLoan
	for i, out := range transfers {
		if out.Standard != events.ERC20 || out.From == (common.Address{}) || out.From == out.To || out.Amount.Sign() == 0 {
			continue
		}
		k := key{out.From, out.Token}
		if seen[k] {
			continue
		}
		repaid := new(big.Int)
		for _, back := range transfers[i+1:] {
			if back.Standard == events.ERC20 && back.Token == out.Token && back.To == out.From && back.From != out.From {
				repaid.Add(repaid, back.Amount)
			}
		}
		if repaid.Cmp(out.Amount) >= 0 {
			seen[k] = true
			loans = append(loans, FlashLoan{Lender: out.From, Token: out.Token, Amount: new(big.Int).Set(out.Amount), Source: RepaidPattern})
		}
	}
	return loans
}

// mergeFlashLoans keeps every protocol-announced loan and adds pattern matches
// for lenders no protocol event already names.
func mergeFlashLoans(announced, repaid []FlashLoan) []FlashLoan {
	named := map[common.Address]bool{}
	for _, l := range announced {
		named[l.Lender] = true
	}
	loans := announced
	for _, l := range repaid {
		if !named[l.Lender] {
			loans = append(loans, l)
		}
	}
	return loans
}
