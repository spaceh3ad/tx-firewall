//go:build integration

package chainstate

import (
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// Runs against a real Anvil (it uses anvil_setCode and anvil_mine). Start one with `anvil`, then:
//
//	CHAINSTATE_RPC=http://127.0.0.1:8545 go test -tags=integration ./internal/chainstate/
func TestFreshnessAnvil(t *testing.T) {
	url := os.Getenv("CHAINSTATE_RPC")
	if url == "" {
		t.Skip("CHAINSTATE_RPC not set")
	}
	client, err := rpc.DialContext(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	eth := ethclient.NewClient(client)

	mine := func(blocks int) {
		t.Helper()
		if err := client.CallContext(t.Context(), nil, "anvil_mine", blocks); err != nil {
			t.Fatal(err)
		}
	}
	mine(20) // give the chain some history before the contract appears

	addr := common.HexToAddress("0x000000000000000000000000000000000000f00d")
	if err := client.CallContext(t.Context(), nil, "anvil_setCode", addr, "0x6080"); err != nil {
		t.Fatal(err)
	}
	mine(1)

	f := NewRPCFreshness(eth, 5, 5*time.Second)
	if err := f.Verify(t.Context()); err != nil {
		t.Fatal(err)
	}

	status := func() Status {
		t.Helper()
		s, err := f.Status(t.Context(), addr)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := status(); s != Fresh {
		t.Fatalf("just deployed: status = %d, want Fresh", s)
	}
	mine(10)
	if s := status(); s != Established {
		t.Fatalf("10 blocks later with a 5-block window: status = %d, want Established", s)
	}
	if s, err := f.Status(t.Context(), common.HexToAddress("0x000000000000000000000000000000000000beef")); err != nil || s != NoCode {
		t.Fatalf("empty address: status = %d, %v, want NoCode", s, err)
	}
}
