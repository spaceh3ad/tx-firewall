// Package chainstate answers questions about on-chain history that the rules
// need, such as whether a contract was deployed recently.
package chainstate

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// FreshnessChecker reports whether a contract was deployed recently.
type FreshnessChecker interface {
	IsFreshContract(ctx context.Context, addr common.Address) (bool, error)
}

// CodeReader is the part of an RPC client freshness needs; *ethclient.Client satisfies it.
type CodeReader interface {
	BlockNumber(ctx context.Context) (uint64, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

// RPCFreshness calls a contract fresh when it has code now but had none
// window blocks ago. Reading code at an old block needs the node to keep that
// much state history: an archive node, Anvil, or a pruned node with a window
// under its history limit (128 blocks for Geth).
type RPCFreshness struct {
	reader  CodeReader
	window  uint64
	timeout time.Duration
}

var _ FreshnessChecker = (*RPCFreshness)(nil)

func NewRPCFreshness(reader CodeReader, window uint64, timeout time.Duration) *RPCFreshness {
	return &RPCFreshness{reader: reader, window: window, timeout: timeout}
}

// Status classifies an address by the age of its code.
type Status int

const (
	NoCode      Status = iota // no code now: not a contract (yet)
	Fresh                     // has code now, had none window blocks ago
	Established               // already had code window blocks ago
)

// StatusReader classifies addresses; the cache needs the full status, not just fresh or not.
type StatusReader interface {
	Status(ctx context.Context, addr common.Address) (Status, error)
}

var _ StatusReader = (*RPCFreshness)(nil)

func (c *RPCFreshness) Status(ctx context.Context, addr common.Address) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	code, err := c.reader.CodeAt(ctx, addr, nil)
	if err != nil {
		return NoCode, fmt.Errorf("code of %s: %w", addr.Hex(), err)
	}
	if len(code) == 0 {
		return NoCode, nil
	}
	past, err := c.pastBlock(ctx)
	if err != nil {
		return NoCode, err
	}
	oldCode, err := c.reader.CodeAt(ctx, addr, past)
	if err != nil {
		return NoCode, fmt.Errorf("code of %s at block %s: %w", addr.Hex(), past, err)
	}
	if len(oldCode) == 0 {
		return Fresh, nil
	}
	return Established, nil
}

// IsFreshContract returns false for addresses without code: they are not
// contracts, so there is no code to be fresh.
func (c *RPCFreshness) IsFreshContract(ctx context.Context, addr common.Address) (bool, error) {
	s, err := c.Status(ctx, addr)
	return s == Fresh, err
}

// Verify checks that the node can read state from window blocks ago, so a
// node without enough history fails at startup instead of on every lookup.
func (c *RPCFreshness) Verify(ctx context.Context) error {
	past, err := c.pastBlock(ctx)
	if err != nil {
		return err
	}
	if _, err := c.reader.CodeAt(ctx, common.Address{}, past); err != nil {
		return fmt.Errorf("node cannot read state at block %s (%d blocks back); use an archive node or a smaller window: %w", past, c.window, err)
	}
	return nil
}

// pastBlock returns the block window blocks before the latest one, or the
// genesis block on a chain younger than the window.
func (c *RPCFreshness) pastBlock(ctx context.Context) (*big.Int, error) {
	latest, err := c.reader.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("latest block: %w", err)
	}
	if latest < c.window {
		return new(big.Int), nil
	}
	return new(big.Int).SetUint64(latest - c.window), nil
}

// CachedFreshness remembers established contracts. That answer never changes:
// established code only gets older, and since EIP-6780 (Cancun) it can no
// longer be selfdestructed and replaced. Fresh answers expire as blocks pass,
// and an address without code may be deployed to at any time (e.g. a
// precomputed CREATE2 address), so both are always looked up again.
type CachedFreshness struct {
	next       StatusReader
	maxEntries int

	mu    sync.Mutex
	known map[common.Address]struct{}
}

var _ FreshnessChecker = (*CachedFreshness)(nil)

func NewCachedFreshness(next StatusReader, maxEntries int) (*CachedFreshness, error) {
	if maxEntries <= 0 {
		return nil, errors.New("freshness cache size must be positive")
	}
	return &CachedFreshness{next: next, maxEntries: maxEntries, known: make(map[common.Address]struct{})}, nil
}

func (c *CachedFreshness) IsFreshContract(ctx context.Context, addr common.Address) (bool, error) {
	c.mu.Lock()
	_, established := c.known[addr]
	c.mu.Unlock()
	if established {
		return false, nil
	}

	s, err := c.next.Status(ctx, addr)
	if err != nil || s != Established {
		return s == Fresh, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.known) >= c.maxEntries {
		clear(c.known) // bounded memory without tracking access order
	}
	c.known[addr] = struct{}{}
	return false, nil
}
