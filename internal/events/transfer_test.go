package events

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Checked against `cast keccak "Transfer(address,address,uint256)"`.
var topicTransfer = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

func TestDecodeTransfer(t *testing.T) {
	amount := new(big.Int).Lsh(big.NewInt(1), 200) // more than fits in a uint64
	tokenID := big.NewInt(42)

	cases := map[string]struct {
		topics []common.Hash
		data   []byte
		want   Transfer
	}{
		"ERC-20": {
			[]common.Hash{topicTransfer, word(alice), word(bob)}, common.BigToHash(amount).Bytes(),
			Transfer{Standard: ERC20, From: alice, To: bob, Amount: amount},
		},
		"ERC-20 mint": {
			[]common.Hash{topicTransfer, {}, word(bob)}, common.BigToHash(big.NewInt(1)).Bytes(),
			Transfer{Standard: ERC20, From: common.Address{}, To: bob, Amount: big.NewInt(1)},
		},
		"ERC-721": {
			[]common.Hash{topicTransfer, word(alice), word(bob), common.BigToHash(tokenID)}, nil,
			Transfer{Standard: ERC721, From: alice, To: bob, TokenID: tokenID},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := DecodeTransfer(token, tc.topics, tc.data)
			if !ok {
				t.Fatal("transfer not recognised")
			}
			if got.Standard != tc.want.Standard || got.Token != token || got.From != tc.want.From || got.To != tc.want.To {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
			if (tc.want.Amount == nil) != (got.Amount == nil) || (got.Amount != nil && got.Amount.Cmp(tc.want.Amount) != 0) {
				t.Errorf("amount = %v, want %v", got.Amount, tc.want.Amount)
			}
			if (tc.want.TokenID == nil) != (got.TokenID == nil) || (got.TokenID != nil && got.TokenID.Cmp(tc.want.TokenID) != 0) {
				t.Errorf("token id = %v, want %v", got.TokenID, tc.want.TokenID)
			}
		})
	}
}

func TestDecodeTransferIgnoresOtherLogs(t *testing.T) {
	cases := map[string]struct {
		topics []common.Hash
		data   []byte
	}{
		"no topics":                {nil, nil},
		"other event":              {[]common.Hash{topicUpgraded, word(bob)}, nil},
		"ERC-20 without amount":    {[]common.Hash{topicTransfer, word(alice), word(bob)}, nil},
		"ERC-20 with extra data":   {[]common.Hash{topicTransfer, word(alice), word(bob)}, make([]byte, 64)},
		"ERC-721 with data":        {[]common.Hash{topicTransfer, word(alice), word(bob), {}}, make([]byte, 32)},
		"non-indexed legacy token": {[]common.Hash{topicTransfer}, make([]byte, 96)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := DecodeTransfer(token, tc.topics, tc.data); ok {
				t.Errorf("decoded %+v", got)
			}
		})
	}
}

// Any log decodes without panicking; when it decodes, the layout matches the
// standard, exactly one of Amount and TokenID is set, and parties round-trip.
func FuzzDecodeTransfer(f *testing.F) {
	f.Add(true, uint8(2), alice.Bytes(), bob.Bytes(), common.BigToHash(big.NewInt(7)).Bytes())
	f.Add(true, uint8(3), alice.Bytes(), bob.Bytes(), []byte{})
	f.Add(false, uint8(2), alice.Bytes(), bob.Bytes(), make([]byte, 32))

	f.Fuzz(func(t *testing.T, isTransfer bool, nIndexed uint8, from, to, data []byte) {
		topics := []common.Hash{topicUpgraded}
		if isTransfer {
			topics[0] = topicTransfer
		}
		args := []common.Hash{common.BytesToHash(from), common.BytesToHash(to), common.BytesToHash(data)}
		topics = append(topics, args[:int(nIndexed%4)]...)

		got, ok := DecodeTransfer(token, topics, data)
		if !ok {
			return
		}
		if !isTransfer {
			t.Fatalf("decoded a non-Transfer log as %+v", got)
		}
		switch got.Standard {
		case ERC20:
			if len(topics) != 3 || len(data) != 32 || got.Amount == nil || got.TokenID != nil {
				t.Fatalf("bad ERC-20 decode %+v from %d topics, %d data bytes", got, len(topics), len(data))
			}
		case ERC721:
			if len(topics) != 4 || len(data) != 0 || got.TokenID == nil || got.Amount != nil {
				t.Fatalf("bad ERC-721 decode %+v from %d topics, %d data bytes", got, len(topics), len(data))
			}
		default:
			t.Fatalf("unknown standard %q", got.Standard)
		}
		if got.From != common.BytesToAddress(common.BytesToHash(from).Bytes()[12:]) ||
			got.To != common.BytesToAddress(common.BytesToHash(to).Bytes()[12:]) {
			t.Fatalf("parties did not round-trip: %+v", got)
		}
	})
}
