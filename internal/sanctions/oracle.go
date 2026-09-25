package sanctions

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ChainalysisOracle is the Chainalysis SanctionsList contract. It is deployed
// at this address on Ethereum mainnet and several other EVM chains.
var ChainalysisOracle = common.HexToAddress("0x40C57923924B5c5c5455c48D93317139ADDaC8fb")

// isSanctionedSelector identifies isSanctioned(address) in calldata (0xdf592f7d).
var isSanctionedSelector = crypto.Keccak256([]byte("isSanctioned(address)"))[:4]

// ContractCaller is the part of an RPC client the oracle needs; *ethclient.Client satisfies it.
type ContractCaller interface {
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

// OracleChecker asks an on-chain sanctions oracle through eth_call.
type OracleChecker struct {
	caller  ContractCaller
	oracle  common.Address
	timeout time.Duration
}

var _ Checker = (*OracleChecker)(nil)

// NewOracleChecker gives each lookup at most timeout to answer.
func NewOracleChecker(caller ContractCaller, oracle common.Address, timeout time.Duration) *OracleChecker {
	return &OracleChecker{caller: caller, oracle: oracle, timeout: timeout}
}

// Verify checks that a contract is deployed at the oracle address, so an RPC
// pointing at the wrong chain is caught at startup instead of on every lookup.
func (c *OracleChecker) Verify(ctx context.Context) error {
	code, err := c.caller.CodeAt(ctx, c.oracle, nil)
	if err != nil {
		return fmt.Errorf("sanctions oracle: %w", err)
	}
	if len(code) == 0 {
		return fmt.Errorf("sanctions oracle: no contract at %s on this chain", c.oracle.Hex())
	}
	return nil
}

func (c *OracleChecker) IsSanctioned(ctx context.Context, addr common.Address) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	out, err := c.caller.CallContract(ctx, ethereum.CallMsg{To: &c.oracle, Data: isSanctionedCalldata(addr)}, nil)
	if err != nil {
		return false, fmt.Errorf("sanctions oracle call: %w", err)
	}
	return decodeBool(out)
}

func isSanctionedCalldata(addr common.Address) []byte {
	data := make([]byte, 0, 4+32)
	data = append(data, isSanctionedSelector...)
	return append(data, common.LeftPadBytes(addr.Bytes(), 32)...)
}

// decodeBool strictly decodes an ABI-encoded bool. Anything else, including the
// empty result of calling an address without code, is an error, never "clean".
func decodeBool(out []byte) (bool, error) {
	if len(out) != 32 {
		return false, fmt.Errorf("sanctions oracle: unexpected response length %d", len(out))
	}
	for _, b := range out[:31] {
		if b != 0 {
			return false, errors.New("sanctions oracle: response is not a bool")
		}
	}
	switch out[31] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("sanctions oracle: response is not a bool")
	}
}
