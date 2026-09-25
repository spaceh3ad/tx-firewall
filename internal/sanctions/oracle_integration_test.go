//go:build integration

package sanctions

import (
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Queries the real Chainalysis oracle. Run with:
//
//	SANCTIONS_ORACLE_RPC=https://ethereum-rpc.publicnode.com go test -tags=integration ./internal/sanctions/
func TestOracleCheckerMainnet(t *testing.T) {
	rpcURL := os.Getenv("SANCTIONS_ORACLE_RPC")
	if rpcURL == "" {
		t.Skip("SANCTIONS_ORACLE_RPC not set")
	}
	client, err := ethclient.DialContext(t.Context(), rpcURL)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	c := NewOracleChecker(client, ChainalysisOracle, 10*time.Second)
	if err := c.Verify(t.Context()); err != nil {
		t.Fatal(err)
	}

	// First entry of config/sanctions.txt; also on the Chainalysis list.
	if !isSanctioned(t, c, common.HexToAddress("0x0330070FD38Ec3bB94F58FA55D40368271E9e54A")) {
		t.Error("known sanctioned address reported clean")
	}
	if isSanctioned(t, c, alice) {
		t.Error("anvil account 0 reported sanctioned")
	}
}
