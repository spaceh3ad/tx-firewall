package events

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TokenStandard tells ERC-20 and ERC-721 transfers apart.
type TokenStandard string

const (
	ERC20  TokenStandard = "ERC-20"
	ERC721 TokenStandard = "ERC-721"
)

// Transfer is a decoded token Transfer event.
type Transfer struct {
	Standard TokenStandard
	Token    common.Address // the token contract that emitted the event
	From, To common.Address
	Amount   *big.Int // ERC-20 only
	TokenID  *big.Int // ERC-721 only
}

var transferTopic = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))

// DecodeTransfer decodes a Transfer event emitted by token. Both standards
// share the same topic0, so the layout decides: ERC-20 indexes from and to
// and puts the amount in data; ERC-721 also indexes the token ID.
// Any other layout is not recognised.
func DecodeTransfer(token common.Address, topics []common.Hash, data []byte) (Transfer, bool) {
	if len(topics) == 0 || topics[0] != transferTopic {
		return Transfer{}, false
	}
	switch {
	case len(topics) == 3 && len(data) == 32:
		return Transfer{
			Standard: ERC20, Token: token,
			From: addressArg(topics[1]), To: addressArg(topics[2]),
			Amount: new(big.Int).SetBytes(data),
		}, true
	case len(topics) == 4 && len(data) == 0:
		return Transfer{
			Standard: ERC721, Token: token,
			From: addressArg(topics[1]), To: addressArg(topics[2]),
			TokenID: topics[3].Big(),
		}, true
	default:
		return Transfer{}, false
	}
}
