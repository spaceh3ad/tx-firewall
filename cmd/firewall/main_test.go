package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var discard = slog.New(slog.DiscardHandler)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sanctions.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewScreenerBlocksListedSender(t *testing.T) {
	sanctioned := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	clean := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

	s, err := newScreener(writeFile(t, "# test list\n"+sanctioned.Hex()+"\n"), 50, discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for from, wantBlock := range map[common.Address]bool{sanctioned: true, clean: false} {
		v, err := s.Screen(t.Context(), &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{}), From: from})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v.Block != wantBlock {
			t.Errorf("sender %s: block = %v, want %v", from, v.Block, wantBlock)
		}
	}
}

func TestNewScreenerRejectsBadConfig(t *testing.T) {
	cases := map[string]struct {
		file      string
		threshold int
	}{
		"missing file":   {filepath.Join(t.TempDir(), "missing.txt"), 50},
		"malformed list": {writeFile(t, "not-an-address\n"), 50},
		"zero threshold": {writeFile(t, ""), 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newScreener(tc.file, tc.threshold, discard); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// The shipped list must stay loadable: a typo in it would stop the firewall from starting.
func TestShippedSanctionsListLoads(t *testing.T) {
	if _, err := newScreener(filepath.Join("..", "..", "config", "sanctions.txt"), 50, discard); err != nil {
		t.Fatalf("config/sanctions.txt does not load: %v", err)
	}
}
