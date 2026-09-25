// Package simulate executes a transaction against the node's current state
// without broadcasting it, and returns its call trace.
package simulate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Simulator traces what a transaction would do.
type Simulator interface {
	Simulate(ctx context.Context, tx *txdecode.Decoded) (*CallFrame, error)
}

// CallFrame is one call in the trace, as returned by geth's callTracer.
// The root frame is the transaction itself; Calls are its sub-calls in execution order.
type CallFrame struct {
	Type    string          `json:"type"` // CALL, STATICCALL, DELEGATECALL, CALLCODE, CREATE, CREATE2, SELFDESTRUCT
	From    common.Address  `json:"from"`
	To      *common.Address `json:"to,omitempty"` // nil for a CREATE that failed
	Value   *hexutil.Big    `json:"value,omitempty"`
	Gas     hexutil.Uint64  `json:"gas"`
	GasUsed hexutil.Uint64  `json:"gasUsed"`
	Input   hexutil.Bytes   `json:"input"`
	Output  hexutil.Bytes   `json:"output,omitempty"`
	Error   string          `json:"error,omitempty"` // set when this frame reverted; its logs and sub-calls were rolled back
	Logs    []Log           `json:"logs,omitempty"`
	Calls   []CallFrame     `json:"calls,omitempty"`
}

// Log is an event emitted by a frame.
type Log struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

// NodeError means the node refused to execute the transaction at all, for
// example because the sender can't pay for it. Such a transaction is invalid,
// unlike a transaction that executes and reverts.
type NodeError struct {
	Message string
}

func (e *NodeError) Error() string { return "node rejected transaction: " + e.Message }

// RPCSimulator runs debug_traceCall with the callTracer on a node that exposes the debug API.
type RPCSimulator struct {
	client  *rpc.Client
	timeout time.Duration
}

var _ Simulator = (*RPCSimulator)(nil)

func NewRPCSimulator(client *rpc.Client, timeout time.Duration) *RPCSimulator {
	return &RPCSimulator{client: client, timeout: timeout}
}

// callArgs is the transaction as debug_traceCall expects it. Fee fields are
// left out on purpose: the simulation is about what the transaction does,
// and the node checks fees itself when the transaction is submitted.
type callArgs struct {
	From  common.Address  `json:"from"`
	To    *common.Address `json:"to,omitempty"`
	Gas   hexutil.Uint64  `json:"gas"`
	Value *hexutil.Big    `json:"value"`
	Input hexutil.Bytes   `json:"input"`
}

func newCallArgs(tx *txdecode.Decoded) callArgs {
	return callArgs{
		From:  tx.From,
		To:    tx.Tx.To(),
		Gas:   hexutil.Uint64(tx.Tx.Gas()),
		Value: (*hexutil.Big)(tx.Tx.Value()),
		Input: tx.Tx.Data(),
	}
}

var traceConfig = map[string]any{
	"tracer":       "callTracer",
	"tracerConfig": map[string]any{"withLog": true},
}

func (s *RPCSimulator) Simulate(ctx context.Context, tx *txdecode.Decoded) (*CallFrame, error) {
	return s.trace(ctx, newCallArgs(tx))
}

// Verify checks that the node supports debug_traceCall with the callTracer,
// so a node without the debug API fails at startup instead of on every transaction.
func (s *RPCSimulator) Verify(ctx context.Context) error {
	// A plain call to the zero address: no code, and enough gas for any node to accept it.
	probe := callArgs{To: &common.Address{}, Gas: 100_000, Value: new(hexutil.Big)}
	if _, err := s.trace(ctx, probe); err != nil {
		return fmt.Errorf("node does not support debug_traceCall with callTracer: %w", err)
	}
	return nil
}

func (s *RPCSimulator) trace(ctx context.Context, args callArgs) (*CallFrame, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var frame CallFrame
	err := s.client.CallContext(ctx, &frame, "debug_traceCall", args, "latest", traceConfig)
	var rpcErr rpc.Error
	switch {
	case errors.As(err, &rpcErr) && isTxRejection(rpcErr.ErrorCode()):
		return nil, &NodeError{Message: rpcErr.Error()}
	case err != nil:
		return nil, fmt.Errorf("debug_traceCall: %w", err)
	case frame.Type == "":
		return nil, errors.New("debug_traceCall: empty trace")
	}
	return &frame, nil
}

// isTxRejection reports whether a JSON-RPC error code means the transaction
// itself is invalid: geth uses -32000 (e.g. "insufficient funds"), Anvil -32003.
// Other codes (method not found, rate limits, internal errors) are
// infrastructure failures, not a verdict on the transaction.
func isTxRejection(code int) bool {
	return code == -32000 || code == -32003
}
