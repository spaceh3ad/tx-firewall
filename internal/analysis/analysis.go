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
	Frames   []Frame          // the call tree flattened in execution order (pre-order)
	Created  []common.Address // contracts deployed by this transaction
	Logs     []simulate.Log   // events that would be emitted, grouped by frame

	Transfers       []events.Transfer
	Approvals       []events.Approval
	ApprovalsForAll []events.ApprovalForAll
	Privileged      []events.PrivilegeChange
}

// Frame is one call of the trace. The root frame has depth 0; a frame's
// sub-calls follow it in Frames with greater depth.
type Frame struct {
	Type  string         // CALL, STATICCALL, DELEGATECALL, CALLCODE, CREATE, CREATE2, SELFDESTRUCT
	From  common.Address // the caller, or the proxy's address for a DELEGATECALL
	To    common.Address // the callee, or the new contract for CREATE and CREATE2
	Depth int
}

// IsCall reports whether the frame executes code at To (as opposed to creating it).
func (f Frame) IsCall() bool {
	switch f.Type {
	case "CALL", "STATICCALL", "DELEGATECALL", "CALLCODE":
		return true
	}
	return false
}

// IsCreate reports whether the frame deploys a contract at To.
func (f Frame) IsCreate() bool {
	return f.Type == "CREATE" || f.Type == "CREATE2"
}

// SubtreeEnd returns the index just past the last descendant of Frames[i],
// so Frames[i+1:SubtreeEnd(i)] are the calls made while Frames[i] was running.
func (a *Analysis) SubtreeEnd(i int) int {
	j := i + 1
	for j < len(a.Frames) && a.Frames[j].Depth > a.Frames[i].Depth {
		j++
	}
	return j
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
	a.collect(trace, 0)
	return a
}

// collect walks the call tree in execution order, skipping reverted subtrees.
func (a *Analysis) collect(f *simulate.CallFrame, depth int) {
	if f.Error != "" {
		return
	}
	frame := Frame{Type: f.Type, From: f.From, Depth: depth}
	if f.To != nil {
		frame.To = *f.To
		a.addAddress(*f.To)
		if frame.IsCreate() {
			a.Created = append(a.Created, *f.To)
		}
	}
	a.Frames = append(a.Frames, frame)
	for _, l := range f.Logs {
		a.Logs = append(a.Logs, l)
		if tr, ok := events.DecodeTransfer(l.Address, l.Topics, l.Data); ok {
			a.Transfers = append(a.Transfers, tr)
			a.addAddress(tr.To)
		}
		if ap, ok := events.DecodeApproval(l.Address, l.Topics, l.Data); ok {
			a.Approvals = append(a.Approvals, ap)
		}
		if ap, ok := events.DecodeApprovalForAll(l.Address, l.Topics, l.Data); ok {
			a.ApprovalsForAll = append(a.ApprovalsForAll, ap)
		}
		if pc, ok := events.DecodePrivilegeChange(l.Address, l.Topics, l.Data); ok {
			a.Privileged = append(a.Privileged, pc)
		}
	}
	for i := range f.Calls {
		a.collect(&f.Calls[i], depth+1)
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
