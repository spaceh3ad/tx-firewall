package analysis

import (
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/spaceh3ad/tx-firewall/internal/txdecode"
)

var (
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
)

// decoded builds a Decoded directly; FromTx never looks at the signature,
// so the transaction doesn't need to be signed.
func decoded(from common.Address, to *common.Address) *txdecode.Decoded {
	return &txdecode.Decoded{Tx: types.NewTx(&types.DynamicFeeTx{To: to}), From: from}
}

func TestFromTxAddresses(t *testing.T) {
	cases := map[string]struct {
		tx   *txdecode.Decoded
		want []common.Address
	}{
		"transfer":          {decoded(alice, &bob), []common.Address{alice, bob}},
		"self transfer":     {decoded(alice, &alice), []common.Address{alice}},
		"contract creation": {decoded(alice, nil), []common.Address{alice}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := FromTx(tc.tx)
			if a.Tx != tc.tx {
				t.Error("Analysis does not keep the decoded transaction")
			}
			if !slices.Equal(a.Addresses, tc.want) {
				t.Errorf("addresses = %v, want %v", a.Addresses, tc.want)
			}
		})
	}
}

// For any sender and recipient: the sender is always listed, the recipient is
// listed exactly when present, and no address appears twice.
func FuzzFromTxAddresses(f *testing.F) {
	f.Add(alice.Bytes(), bob.Bytes(), false)
	f.Add(alice.Bytes(), alice.Bytes(), false)
	f.Add(alice.Bytes(), []byte{}, true)

	f.Fuzz(func(t *testing.T, fromBytes, toBytes []byte, create bool) {
		from := common.BytesToAddress(fromBytes)
		var to *common.Address
		if !create {
			addr := common.BytesToAddress(toBytes)
			to = &addr
		}

		got := FromTx(decoded(from, to)).Addresses

		if !slices.Contains(got, from) {
			t.Fatalf("sender %s missing from %v", from, got)
		}
		if to != nil && !slices.Contains(got, *to) {
			t.Fatalf("recipient %s missing from %v", *to, got)
		}
		if to == nil && len(got) != 1 {
			t.Fatalf("contract creation should list only the sender, got %v", got)
		}
		seen := map[common.Address]bool{}
		for _, a := range got {
			if seen[a] {
				t.Fatalf("duplicate address %s in %v", a, got)
			}
			seen[a] = true
		}
	})
}
