// Package events decodes the contract events the rules look for from raw logs.
package events

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// PrivilegeKind names an event that changes who controls a contract.
type PrivilegeKind string

const (
	OwnershipTransferred PrivilegeKind = "OwnershipTransferred" // Ownable
	Upgraded             PrivilegeKind = "Upgraded"             // EIP-1967 proxy implementation
	AdminChanged         PrivilegeKind = "AdminChanged"         // EIP-1967 proxy admin
	RoleGranted          PrivilegeKind = "RoleGranted"          // AccessControl
)

// PrivilegeChange is a decoded privilege event.
type PrivilegeChange struct {
	Kind     PrivilegeKind
	Contract common.Address // the contract that emitted the event
	// Subject gains the privilege: the new owner, implementation or admin, or the role grantee.
	Subject  common.Address
	Previous common.Address // previous owner or admin; zero for Upgraded and RoleGranted
	Role     common.Hash    // RoleGranted only
}

type privilegeEvent struct {
	kind  PrivilegeKind
	nargs int
	build func(args []common.Hash) PrivilegeChange
}

var privilegeEvents = map[common.Hash]privilegeEvent{
	crypto.Keccak256Hash([]byte("OwnershipTransferred(address,address)")): {OwnershipTransferred, 2,
		func(a []common.Hash) PrivilegeChange {
			return PrivilegeChange{Previous: addressArg(a[0]), Subject: addressArg(a[1])}
		}},
	crypto.Keccak256Hash([]byte("Upgraded(address)")): {Upgraded, 1,
		func(a []common.Hash) PrivilegeChange {
			return PrivilegeChange{Subject: addressArg(a[0])}
		}},
	crypto.Keccak256Hash([]byte("AdminChanged(address,address)")): {AdminChanged, 2,
		func(a []common.Hash) PrivilegeChange {
			return PrivilegeChange{Previous: addressArg(a[0]), Subject: addressArg(a[1])}
		}},
	crypto.Keccak256Hash([]byte("RoleGranted(bytes32,address,address)")): {RoleGranted, 3,
		func(a []common.Hash) PrivilegeChange {
			return PrivilegeChange{Role: a[0], Subject: addressArg(a[1])}
		}},
}

// DecodePrivilegeChange decodes a log emitted by contract. It returns false
// for any other event, or when the arguments don't match the event's shape.
//
// Arguments are read from the indexed topics first, then from the data words,
// so an event is recognised whether or not its arguments are indexed (e.g.
// OpenZeppelin's AdminChanged is not indexed, most others are).
func DecodePrivilegeChange(contract common.Address, topics []common.Hash, data []byte) (PrivilegeChange, bool) {
	if len(topics) == 0 {
		return PrivilegeChange{}, false
	}
	ev, ok := privilegeEvents[topics[0]]
	if !ok {
		return PrivilegeChange{}, false
	}
	args, ok := eventArgs(topics[1:], data)
	if !ok || len(args) != ev.nargs {
		return PrivilegeChange{}, false
	}
	pc := ev.build(args)
	pc.Kind = ev.kind
	pc.Contract = contract
	return pc, true
}

// eventArgs joins indexed topics and 32-byte data words into one argument list.
func eventArgs(indexed []common.Hash, data []byte) ([]common.Hash, bool) {
	if len(data)%32 != 0 {
		return nil, false
	}
	args := make([]common.Hash, 0, len(indexed)+len(data)/32)
	args = append(args, indexed...)
	for i := 0; i < len(data); i += 32 {
		args = append(args, common.BytesToHash(data[i:i+32]))
	}
	return args, true
}

func addressArg(word common.Hash) common.Address {
	return common.BytesToAddress(word[12:])
}
