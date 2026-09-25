//go:build integration

package simulate

import (
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

// Runs against a real node. Start one with `anvil`, then:
//
//	SIMULATE_RPC=http://127.0.0.1:8545 go test -tags=integration ./internal/simulate/
func TestSimulateAnvil(t *testing.T) {
	url := os.Getenv("SIMULATE_RPC")
	if url == "" {
		t.Skip("SIMULATE_RPC not set")
	}
	client, err := rpc.DialContext(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sim := NewRPCSimulator(client, 5*time.Second)

	if err := sim.Verify(t.Context()); err != nil {
		t.Fatal(err)
	}

	create := func(from common.Address, value int64, initCode []byte) *txdecode.Decoded {
		return &txdecode.Decoded{
			Tx:   types.NewTx(&types.DynamicFeeTx{Gas: 1_000_000, Value: big.NewInt(value), Data: initCode}),
			From: from,
		}
	}

	t.Run("create that emits a log", func(t *testing.T) {
		// PUSH1 0 PUSH1 0 LOG0 STOP
		frame, err := sim.Simulate(t.Context(), create(alice, 0, []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}))
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != "CREATE" || frame.Error != "" || frame.To == nil || len(frame.Logs) != 1 {
			t.Errorf("frame = %+v", frame)
		}
	})

	t.Run("create that reverts", func(t *testing.T) {
		// PUSH1 0 PUSH1 0 LOG0, then PUSH1 0 PUSH1 0 REVERT
		frame, err := sim.Simulate(t.Context(), create(alice, 0, []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x60, 0x00, 0x60, 0x00, 0xfd}))
		if err != nil {
			t.Fatal(err)
		}
		if frame.Error == "" {
			t.Errorf("reverted frame has no error: %+v", frame)
		}
	})

	t.Run("sender cannot pay", func(t *testing.T) {
		_, err := sim.Simulate(t.Context(), create(common.HexToAddress("0xabc"), 1, nil))
		var nodeErr *NodeError
		if !errors.As(err, &nodeErr) {
			t.Errorf("err = %v, want a NodeError", err)
		}
	})
}
