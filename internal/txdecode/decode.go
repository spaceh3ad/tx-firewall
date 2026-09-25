// Package txdecode turns the raw hex payload of eth_sendRawTransaction
// into a transaction and recovers its sender from the signature.
package txdecode

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// Decoded is a signed transaction together with its recovered sender.
type Decoded struct {
	Tx   *types.Transaction
	From common.Address
}

// DecodeRawTransaction parses the params of an eth_sendRawTransaction call,
// which must be a JSON array with exactly one hex-encoded signed transaction.
func DecodeRawTransaction(params json.RawMessage) (*Decoded, error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("params must be an array of strings: %w", err)
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("expected exactly 1 param, got %d", len(args))
	}

	raw, err := hexutil.Decode(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	// UnmarshalBinary handles every transaction type: legacy, EIP-2930, EIP-1559, blob, EIP-7702.
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("invalid transaction encoding: %w", err)
	}

	// The sender is not stored in the transaction; it is recovered from the signature.
	signer := types.LatestSignerForChainID(tx.ChainId())
	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	return &Decoded{Tx: tx, From: from}, nil
}
