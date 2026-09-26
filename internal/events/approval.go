package events

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Approval is a decoded ERC-20 Approval event.
type Approval struct {
	Token   common.Address // the token contract that emitted the event
	Owner   common.Address
	Spender common.Address
	Amount  *big.Int
}

// ApprovalForAll is a decoded ERC-721/ERC-1155 ApprovalForAll event.
type ApprovalForAll struct {
	Collection common.Address // the NFT contract that emitted the event
	Owner      common.Address
	Operator   common.Address
	Approved   bool
}

var (
	approvalTopic       = crypto.Keccak256Hash([]byte("Approval(address,address,uint256)"))
	approvalForAllTopic = crypto.Keccak256Hash([]byte("ApprovalForAll(address,address,bool)"))
)

// DecodeApproval decodes an ERC-20 Approval: owner and spender indexed, amount
// in data. ERC-721 also emits Approval, with the token ID indexed and no data;
// that single-token approval is not recognised here.
func DecodeApproval(token common.Address, topics []common.Hash, data []byte) (Approval, bool) {
	if len(topics) != 3 || topics[0] != approvalTopic || len(data) != 32 {
		return Approval{}, false
	}
	return Approval{
		Token:   token,
		Owner:   addressArg(topics[1]),
		Spender: addressArg(topics[2]),
		Amount:  new(big.Int).SetBytes(data),
	}, true
}

// DecodeApprovalForAll decodes ApprovalForAll: owner and operator indexed,
// the flag in data. Any non-zero flag counts as approved, erring towards
// detection rather than trusting a malformed encoding.
func DecodeApprovalForAll(collection common.Address, topics []common.Hash, data []byte) (ApprovalForAll, bool) {
	if len(topics) != 3 || topics[0] != approvalForAllTopic || len(data) != 32 {
		return ApprovalForAll{}, false
	}
	return ApprovalForAll{
		Collection: collection,
		Owner:      addressArg(topics[1]),
		Operator:   addressArg(topics[2]),
		Approved:   common.BytesToHash(data) != common.Hash{},
	}, true
}
