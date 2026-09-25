// Package analysis prepares a transaction for the rules. Everything the rules
// need is computed once here, so rules only read plain data.
package analysis

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Analysis is the rule-ready view of a single transaction.
type Analysis struct {
	Tx *txdecode.Decoded

	// Addresses lists every address the transaction touches, without duplicates.
	// Without simulation this is the sender and, unless the transaction deploys
	// a contract, the recipient.
	Addresses []common.Address
}

// FromTx builds an Analysis from the decoded transaction alone, without simulating it.
func FromTx(tx *txdecode.Decoded) *Analysis {
	addrs := []common.Address{tx.From}
	if to := tx.Tx.To(); to != nil && *to != tx.From {
		addrs = append(addrs, *to)
	}
	return &Analysis{Tx: tx, Addresses: addrs}
}
