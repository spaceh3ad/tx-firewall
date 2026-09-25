package events

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	token = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	role  = common.HexToHash("0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6") // keccak("MINTER_ROLE")

	// Topic hashes checked against `cast keccak "<signature>"`.
	topicOwnershipTransferred = common.HexToHash("0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0")
	topicUpgraded             = common.HexToHash("0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b")
	topicAdminChanged         = common.HexToHash("0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f")
	topicRoleGranted          = common.HexToHash("0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d")
)

func word(a common.Address) common.Hash { return common.BytesToHash(a.Bytes()) }

func data(words ...common.Hash) []byte {
	var out []byte
	for _, w := range words {
		out = append(out, w.Bytes()...)
	}
	return out
}

func TestDecodePrivilegeChange(t *testing.T) {
	cases := map[string]struct {
		topics []common.Hash
		data   []byte
		want   PrivilegeChange
	}{
		"OwnershipTransferred (indexed)": {
			[]common.Hash{topicOwnershipTransferred, word(alice), word(bob)}, nil,
			PrivilegeChange{Kind: OwnershipTransferred, Previous: alice, Subject: bob},
		},
		"OwnershipTransferred (not indexed)": {
			[]common.Hash{topicOwnershipTransferred}, data(word(alice), word(bob)),
			PrivilegeChange{Kind: OwnershipTransferred, Previous: alice, Subject: bob},
		},
		"Upgraded": {
			[]common.Hash{topicUpgraded, word(bob)}, nil,
			PrivilegeChange{Kind: Upgraded, Subject: bob},
		},
		"AdminChanged (OpenZeppelin, not indexed)": {
			[]common.Hash{topicAdminChanged}, data(word(alice), word(bob)),
			PrivilegeChange{Kind: AdminChanged, Previous: alice, Subject: bob},
		},
		"RoleGranted": {
			[]common.Hash{topicRoleGranted, role, word(bob), word(alice)}, nil,
			PrivilegeChange{Kind: RoleGranted, Role: role, Subject: bob},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := DecodePrivilegeChange(token, tc.topics, tc.data)
			if !ok {
				t.Fatal("event not recognised")
			}
			tc.want.Contract = token
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDecodePrivilegeChangeIgnoresOtherLogs(t *testing.T) {
	transfer := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
	cases := map[string]struct {
		topics []common.Hash
		data   []byte
	}{
		"no topics (LOG0)":            {nil, nil},
		"ERC-20 Transfer":             {[]common.Hash{transfer, word(alice), word(bob)}, data(common.BigToHash(common.Big1))},
		"too few args":                {[]common.Hash{topicOwnershipTransferred, word(alice)}, nil},
		"too many args":               {[]common.Hash{topicUpgraded, word(alice)}, data(word(bob))},
		"data not whole words":        {[]common.Hash{topicAdminChanged}, make([]byte, 63)},
		"RoleGranted missing account": {[]common.Hash{topicRoleGranted, role}, data(word(alice))},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := DecodePrivilegeChange(token, tc.topics, tc.data); ok {
				t.Errorf("decoded %+v from a log that is not a privilege change", got)
			}
		})
	}
}

// Any log decodes without panicking. When it decodes, the result names the
// emitting contract and the kind matching topic0, and the argument count fits.
func FuzzDecodePrivilegeChange(f *testing.F) {
	f.Add(uint8(0), uint8(2), []byte(nil))
	f.Add(uint8(2), uint8(0), data(word(alice), word(bob)))
	f.Add(uint8(3), uint8(3), []byte{})
	f.Add(uint8(9), uint8(1), make([]byte, 33))

	known := []common.Hash{topicOwnershipTransferred, topicUpgraded, topicAdminChanged, topicRoleGranted}
	kinds := []PrivilegeKind{OwnershipTransferred, Upgraded, AdminChanged, RoleGranted}
	nargs := []int{2, 1, 2, 3}

	f.Fuzz(func(t *testing.T, event, nIndexed uint8, raw []byte) {
		topics := []common.Hash{common.BytesToHash(raw)} // mostly unknown events
		ev := int(event) % (len(known) + 1)
		if ev < len(known) {
			topics[0] = known[ev]
		}
		for i := range int(nIndexed % 5) {
			topics = append(topics, common.BytesToHash([]byte{byte(i), 0xaa}))
		}

		got, ok := DecodePrivilegeChange(token, topics, raw)
		if !ok {
			return
		}
		if ev == len(known) {
			t.Fatalf("decoded an unknown topic0 as %+v", got)
		}
		if got.Kind != kinds[ev] || got.Contract != token {
			t.Fatalf("decoded %+v for %s", got, kinds[ev])
		}
		if len(topics)-1+len(raw)/32 != nargs[ev] || len(raw)%32 != 0 {
			t.Fatalf("accepted %d topics and %d data bytes for %s", len(topics), len(raw), kinds[ev])
		}
	})
}

// Encoding an event in any indexed/non-indexed split and decoding it gives back the same values.
func FuzzPrivilegeChangeRoundTrip(f *testing.F) {
	f.Add(alice.Bytes(), bob.Bytes(), uint8(0))
	f.Add(bob.Bytes(), alice.Bytes(), uint8(1))

	f.Fuzz(func(t *testing.T, prevBytes, subjectBytes []byte, split uint8) {
		prev, subject := common.BytesToAddress(prevBytes), common.BytesToAddress(subjectBytes)
		args := []common.Hash{word(prev), word(subject)}
		n := int(split % 3) // how many args are indexed

		for _, topic0 := range []common.Hash{topicOwnershipTransferred, topicAdminChanged} {
			topics := append([]common.Hash{topic0}, args[:n]...)
			got, ok := DecodePrivilegeChange(token, topics, data(args[n:]...))
			if !ok || got.Previous != prev || got.Subject != subject {
				t.Fatalf("round trip with %d indexed args: got %+v ok=%v", n, got, ok)
			}
		}
	})
}
