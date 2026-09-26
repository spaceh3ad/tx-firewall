// Package analysis prepares a transaction for the rules. Everything the rules
// need is computed once here, so rules only read plain data.
package analysis

import (
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/events"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Analysis is the rule-ready view of a single transaction.
type Analysis struct {
	Tx *txdecode.Decoded

	// Addresses lists every address the transaction touches, without duplicates:
	// the sender, the recipient, and after simulation also every called or
	// created contract (including delegatecall targets) and every token
	// Transfer recipient.
	Addresses []common.Address

	// The fields below come from simulation and are empty without it.
	// Only frames that did not revert contribute: a reverted frame's logs and
	// sub-calls are rolled back on-chain, even though the trace still shows them.

	Reverted bool             // the whole transaction reverts
	Created  []common.Address // contracts deployed by this transaction
	Logs     []simulate.Log   // events that would be emitted, grouped by frame

	Transfers  []events.Transfer
	Privileged []events.PrivilegeChange
}

// FromTx builds an Analysis from the decoded transaction alone, without simulating it.
func FromTx(tx *txdecode.Decoded) *Analysis {
	addrs := []common.Address{tx.From}
	if to := tx.Tx.To(); to != nil && *to != tx.From {
		addrs = append(addrs, *to)
	}
	return &Analysis{Tx: tx, Addresses: addrs}
}

// Build builds an Analysis from the decoded transaction and its simulated call trace.
func Build(tx *txdecode.Decoded, trace *simulate.CallFrame) *Analysis {
	a := FromTx(tx)
	if trace == nil {
		return a
	}
	a.Reverted = trace.Error != ""
	a.collect(trace)
	return a
}

// collect walks the call tree in execution order, skipping reverted subtrees.
func (a *Analysis) collect(f *simulate.CallFrame) {
	if f.Error != "" {
		return
	}
	if f.To != nil {
		a.addAddress(*f.To)
		if f.Type == "CREATE" || f.Type == "CREATE2" {
			a.Created = append(a.Created, *f.To)
		}
	}
	for _, l := range f.Logs {
		a.Logs = append(a.Logs, l)
		if tr, ok := events.DecodeTransfer(l.Address, l.Topics, l.Data); ok {
			a.Transfers = append(a.Transfers, tr)
			a.addAddress(tr.To)
		}
		if pc, ok := events.DecodePrivilegeChange(l.Address, l.Topics, l.Data); ok {
			a.Privileged = append(a.Privileged, pc)
		}
	}
	for i := range f.Calls {
		a.collect(&f.Calls[i])
	}
}

// addAddress appends addr unless it is already listed. A transaction touches
// at most a few dozen addresses, so a linear scan is cheaper than a set.
func (a *Analysis) addAddress(addr common.Address) {
	if !slices.Contains(a.Addresses, addr) {
		a.Addresses = append(a.Addresses, addr)
	}
}

// CreatedInTx reports whether addr is a contract deployed by this transaction.
func (a *Analysis) CreatedInTx(addr common.Address) bool {
	return slices.Contains(a.Created, addr)
}
