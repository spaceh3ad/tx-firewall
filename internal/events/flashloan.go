package events

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// FlashLoanEvent is a flash loan announced by a known lending protocol.
type FlashLoanEvent struct {
	Protocol string
	Lender   common.Address // the pool or vault that emitted the event
	Token    common.Address // zero when the event doesn't name it (Uniswap V3)
	Amount   *big.Int       // nil when the event doesn't name a single amount (Uniswap V3)
}

var (
	// FlashLoan(address indexed target, address initiator, address indexed asset,
	//   uint256 amount, uint8 interestRateMode, uint256 premium, uint16 indexed referralCode)
	aaveV3FlashLoanTopic = crypto.Keccak256Hash([]byte("FlashLoan(address,address,address,uint256,uint8,uint256,uint16)"))
	// FlashLoan(address indexed recipient, address indexed token, uint256 amount, uint256 feeAmount)
	balancerV2FlashLoanTopic = crypto.Keccak256Hash([]byte("FlashLoan(address,address,uint256,uint256)"))
	// Flash(address indexed sender, address indexed recipient,
	//   uint256 amount0, uint256 amount1, uint256 paid0, uint256 paid1)
	uniswapV3FlashTopic = crypto.Keccak256Hash([]byte("Flash(address,address,uint256,uint256,uint256,uint256)"))
)

// DecodeFlashLoan recognises the flash-loan events of Aave V3, Balancer V2
// and Uniswap V3 pools, checking each event's exact layout.
func DecodeFlashLoan(lender common.Address, topics []common.Hash, data []byte) (FlashLoanEvent, bool) {
	if len(topics) == 0 {
		return FlashLoanEvent{}, false
	}
	switch {
	case topics[0] == aaveV3FlashLoanTopic && len(topics) == 4 && len(data) == 4*32:
		return FlashLoanEvent{
			Protocol: "Aave V3", Lender: lender,
			Token:  addressArg(topics[2]),
			Amount: new(big.Int).SetBytes(data[32:64]),
		}, true
	case topics[0] == balancerV2FlashLoanTopic && len(topics) == 3 && len(data) == 2*32:
		return FlashLoanEvent{
			Protocol: "Balancer V2", Lender: lender,
			Token:  addressArg(topics[2]),
			Amount: new(big.Int).SetBytes(data[:32]),
		}, true
	case topics[0] == uniswapV3FlashTopic && len(topics) == 3 && len(data) == 4*32:
		return FlashLoanEvent{Protocol: "Uniswap V3", Lender: lender}, true
	}
	return FlashLoanEvent{}, false
}
