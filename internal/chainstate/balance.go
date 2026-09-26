package chainstate

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// BalanceReader reads what a holder owns before the transaction runs.
type BalanceReader interface {
	// Balance returns the holder's balance of an ERC-20 token, or of ETH when
	// asset is the zero address. ok is false when the token has no usable
	// balanceOf (it reverts or returns something that isn't a uint256).
	Balance(ctx context.Context, asset, holder common.Address) (balance *big.Int, ok bool, err error)
}

// BalanceClient is the part of an RPC client balances need; *ethclient.Client satisfies it.
type BalanceClient interface {
	BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// RPCBalances reads balances at the latest block, the state the simulated
// transaction starts from.
type RPCBalances struct {
	client  BalanceClient
	timeout time.Duration
}

var _ BalanceReader = (*RPCBalances)(nil)

func NewRPCBalances(client BalanceClient, timeout time.Duration) *RPCBalances {
	return &RPCBalances{client: client, timeout: timeout}
}

// balanceOfSelector identifies balanceOf(address) in calldata (0x70a08231).
var balanceOfSelector = crypto.Keccak256([]byte("balanceOf(address)"))[:4]

func (b *RPCBalances) Balance(ctx context.Context, asset, holder common.Address) (*big.Int, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	if asset == (common.Address{}) {
		bal, err := b.client.BalanceAt(ctx, holder, nil)
		if err != nil {
			return nil, false, fmt.Errorf("ETH balance of %s: %w", holder.Hex(), err)
		}
		return bal, true, nil
	}

	data := make([]byte, 0, 4+32)
	data = append(data, balanceOfSelector...)
	data = append(data, common.LeftPadBytes(holder.Bytes(), 32)...)
	out, err := b.client.CallContract(ctx, ethereum.CallMsg{To: &asset, Data: data}, nil)

	// The node answering with a JSON-RPC error means the call itself failed
	// (e.g. balanceOf reverted): the token just can't be measured. A transport
	// error or timeout means we don't know, and must not be treated as "fine".
	var rpcErr rpc.Error
	if errors.As(err, &rpcErr) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("balance of %s in %s: %w", holder.Hex(), asset.Hex(), err)
	}
	if len(out) != 32 {
		return nil, false, nil
	}
	return new(big.Int).SetBytes(out), true, nil
}
