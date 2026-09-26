package events

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
)

// Checked against `cast keccak "<signature>"`.
var (
	topicApproval       = common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")
	topicApprovalForAll = common.HexToHash("0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31")
)

func TestDecodeApproval(t *testing.T) {
	got, ok := DecodeApproval(token, []common.Hash{topicApproval, word(alice), word(bob)}, math.MaxBig256.Bytes())
	if !ok {
		t.Fatal("approval not recognised")
	}
	if got.Token != token || got.Owner != alice || got.Spender != bob || got.Amount.Cmp(math.MaxBig256) != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestDecodeApprovalIgnoresOtherLogs(t *testing.T) {
	cases := map[string]struct {
		topics []common.Hash
		data   []byte
	}{
		"ERC-721 single approval": {[]common.Hash{topicApproval, word(alice), word(bob), common.BigToHash(big.NewInt(7))}, nil},
		"missing amount":          {[]common.Hash{topicApproval, word(alice), word(bob)}, nil},
		"ApprovalForAll":          {[]common.Hash{topicApprovalForAll, word(alice), word(bob)}, make([]byte, 32)},
		"Transfer":                {[]common.Hash{topicTransfer, word(alice), word(bob)}, make([]byte, 32)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := DecodeApproval(token, tc.topics, tc.data); ok {
				t.Errorf("decoded %+v", got)
			}
		})
	}
}

func TestDecodeApprovalForAll(t *testing.T) {
	cases := map[string]struct {
		flag common.Hash
		want bool
	}{
		"approved":             {common.BigToHash(common.Big1), true},
		"revoked":              {common.Hash{}, false},
		"non-canonical true":   {common.BigToHash(big.NewInt(2)), true},
		"garbage in high byte": {common.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000000"), true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := DecodeApprovalForAll(token, []common.Hash{topicApprovalForAll, word(alice), word(bob)}, tc.flag.Bytes())
			if !ok {
				t.Fatal("ApprovalForAll not recognised")
			}
			if got.Collection != token || got.Owner != alice || got.Operator != bob || got.Approved != tc.want {
				t.Errorf("got %+v, want approved=%v", got, tc.want)
			}
		})
	}
	if _, ok := DecodeApprovalForAll(token, []common.Hash{topicApprovalForAll, word(alice), word(bob)}, nil); ok {
		t.Error("decoded ApprovalForAll without a flag")
	}
}

// Any log decodes without panicking, and each decoder only accepts its own
// topic with exactly two indexed addresses and one data word.
func FuzzDecodeApprovals(f *testing.F) {
	f.Add(uint8(0), uint8(2), alice.Bytes(), make([]byte, 32))
	f.Add(uint8(1), uint8(2), bob.Bytes(), common.BigToHash(common.Big1).Bytes())
	f.Add(uint8(2), uint8(3), []byte{}, []byte{})

	topic0s := []common.Hash{topicApproval, topicApprovalForAll, topicTransfer}

	f.Fuzz(func(t *testing.T, which, nIndexed uint8, addr, data []byte) {
		topics := []common.Hash{topic0s[int(which)%len(topic0s)]}
		for range int(nIndexed % 4) {
			topics = append(topics, common.BytesToHash(addr))
		}

		if a, ok := DecodeApproval(token, topics, data); ok {
			if topics[0] != topicApproval || len(topics) != 3 || len(data) != 32 || a.Amount.Cmp(new(big.Int).SetBytes(data)) != 0 {
				t.Fatalf("bad Approval decode %+v", a)
			}
		}
		if a, ok := DecodeApprovalForAll(token, topics, data); ok {
			if topics[0] != topicApprovalForAll || len(topics) != 3 || len(data) != 32 {
				t.Fatalf("bad ApprovalForAll decode %+v", a)
			}
			if a.Approved != (new(big.Int).SetBytes(data).Sign() != 0) {
				t.Fatalf("approved = %v for data %x", a.Approved, data)
			}
		}
	})
}
