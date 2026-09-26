package analysis

import (
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spaceh3ad/tx-firewall/internal/events"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
)

var (
	carol    = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	proxy    = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	newImpl  = common.HexToAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")
	upgraded = crypto.Keccak256Hash([]byte("Upgraded(address)"))
)

func upgradedLog(contract, impl common.Address) simulate.Log {
	return simulate.Log{Address: contract, Topics: []common.Hash{upgraded, common.BytesToHash(impl.Bytes())}}
}

func plainLog(contract common.Address, id byte) simulate.Log {
	return simulate.Log{Address: contract, Topics: []common.Hash{common.BytesToHash([]byte{id})}}
}

func addrPtr(a common.Address) *common.Address { return &a }

func TestBuildWithoutTraceMatchesFromTx(t *testing.T) {
	a := Build(decoded(alice, &bob), nil)
	if len(a.Addresses) != 2 || a.Reverted || a.Logs != nil || a.Created != nil {
		t.Errorf("got %+v", a)
	}
}

func TestBuildCollectsLogsAndPrivilegeChanges(t *testing.T) {
	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(proxy),
		Logs: []simulate.Log{plainLog(proxy, 1)},
		Calls: []simulate.CallFrame{
			{Type: "DELEGATECALL", From: proxy, To: addrPtr(carol), Logs: []simulate.Log{upgradedLog(proxy, newImpl)}},
		},
	}
	a := Build(decoded(alice, &proxy), trace)

	if len(a.Logs) != 2 {
		t.Fatalf("got %d logs, want 2", len(a.Logs))
	}
	want := events.PrivilegeChange{Kind: events.Upgraded, Contract: proxy, Subject: newImpl}
	if len(a.Privileged) != 1 || a.Privileged[0] != want {
		t.Errorf("privileged = %+v, want [%+v]", a.Privileged, want)
	}
	if a.Reverted {
		t.Error("successful transaction marked reverted")
	}
}

func TestBuildSkipsRevertedSubtrees(t *testing.T) {
	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(proxy),
		Logs: []simulate.Log{plainLog(proxy, 1)},
		Calls: []simulate.CallFrame{
			{
				Type: "CALL", From: proxy, To: addrPtr(carol), Error: "execution reverted",
				Logs: []simulate.Log{upgradedLog(proxy, newImpl)},
				Calls: []simulate.CallFrame{
					{Type: "CREATE", From: carol, To: addrPtr(newImpl), Logs: []simulate.Log{plainLog(newImpl, 2)}},
				},
			},
			{Type: "CALL", From: proxy, To: addrPtr(bob), Logs: []simulate.Log{plainLog(bob, 3)}},
		},
	}
	a := Build(decoded(alice, &proxy), trace)

	if len(a.Logs) != 2 || a.Logs[0].Address != proxy || a.Logs[1].Address != bob {
		t.Errorf("logs = %+v, want the root's and bob's only", a.Logs)
	}
	if len(a.Privileged) != 0 {
		t.Errorf("privilege change from a reverted frame was kept: %+v", a.Privileged)
	}
	if len(a.Created) != 0 {
		t.Errorf("contract created under a reverted frame was kept: %v", a.Created)
	}
}

func TestBuildRevertedTransaction(t *testing.T) {
	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(proxy), Error: "execution reverted",
		Logs: []simulate.Log{upgradedLog(proxy, newImpl)},
	}
	a := Build(decoded(alice, &proxy), trace)

	if !a.Reverted {
		t.Error("reverted transaction not marked")
	}
	if len(a.Logs) != 0 || len(a.Privileged) != 0 {
		t.Errorf("reverted transaction kept effects: %+v", a)
	}
	if len(a.Addresses) != 2 {
		t.Errorf("addresses must still come from the transaction, got %v", a.Addresses)
	}
}

func TestBuildCollectsTouchedAddresses(t *testing.T) {
	token := common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	lib := common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")
	unreachable := common.HexToAddress("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707")
	recipient := common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9")
	transfer := crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))

	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(proxy),
		Calls: []simulate.CallFrame{
			{Type: "DELEGATECALL", From: proxy, To: addrPtr(lib)},
			{Type: "CALL", From: proxy, To: addrPtr(token), Logs: []simulate.Log{{
				Address: token,
				Topics:  []common.Hash{transfer, common.BytesToHash(proxy.Bytes()), common.BytesToHash(recipient.Bytes())},
				Data:    common.BigToHash(common.Big1).Bytes(),
			}}},
			{Type: "CALL", From: proxy, To: addrPtr(unreachable), Error: "execution reverted"},
			{Type: "STATICCALL", From: proxy, To: addrPtr(lib)}, // already listed
		},
	}
	a := Build(decoded(alice, &proxy), trace)

	want := []common.Address{alice, proxy, lib, token, recipient}
	if !slices.Equal(a.Addresses, want) {
		t.Errorf("addresses = %v, want %v", a.Addresses, want)
	}
	if len(a.Transfers) != 1 || a.Transfers[0].To != recipient || a.Transfers[0].Token != token {
		t.Errorf("transfers = %+v", a.Transfers)
	}
}

func TestBuildCreatedContracts(t *testing.T) {
	trace := &simulate.CallFrame{
		Type: "CREATE", From: alice, To: addrPtr(proxy),
		Calls: []simulate.CallFrame{
			{Type: "CREATE2", From: proxy, To: addrPtr(newImpl)},
			{Type: "CREATE", From: proxy, Error: "out of gas"}, // failed create has no address
			{Type: "CALL", From: proxy, To: addrPtr(carol)},
		},
	}
	a := Build(decoded(alice, nil), trace)

	if len(a.Created) != 2 || a.Created[0] != proxy || a.Created[1] != newImpl {
		t.Errorf("created = %v, want [%s %s]", a.Created, proxy, newImpl)
	}
	if !a.CreatedInTx(newImpl) || a.CreatedInTx(carol) {
		t.Error("CreatedInTx disagrees with Created")
	}
}

// treeFrom builds a call tree from fuzz bytes. Each frame consumes one byte:
// bit 0 reverted, bits 1-2 number of logs, bit 3 CREATE, bits 4-5 children.
func treeFrom(data []byte, pos *int, depth int) simulate.CallFrame {
	var b byte
	if *pos < len(data) {
		b = data[*pos]
	}
	*pos++

	f := simulate.CallFrame{Type: "CALL", To: addrPtr(common.BytesToAddress([]byte{byte(*pos)}))}
	if b&0x01 != 0 {
		f.Error = "execution reverted"
	}
	if b&0x08 != 0 {
		f.Type = "CREATE"
	}
	for i := range int(b>>1) & 0x03 {
		f.Logs = append(f.Logs, plainLog(*f.To, byte(i)))
	}
	if depth < 4 {
		for range int(b>>4) & 0x03 {
			if *pos >= len(data) {
				break
			}
			f.Calls = append(f.Calls, treeFrom(data, pos, depth+1))
		}
	}
	return f
}

// Model check: Build keeps exactly the logs, creations and addresses of frames
// with no reverted ancestor (including themselves), and none from anywhere else.
func FuzzBuildSkipsReverted(f *testing.F) {
	f.Add([]byte{0x02})
	f.Add([]byte{0x34, 0x03, 0x0a})
	f.Add([]byte{0x31, 0x02, 0x0e})
	f.Add([]byte{0x2e, 0x2e, 0x2e, 0x07})

	f.Fuzz(func(t *testing.T, data []byte) {
		pos := 0
		root := treeFrom(data, &pos, 0)

		wantLogs, wantCreated := 0, 0
		wantAddrs := map[common.Address]bool{alice: true, bob: true}
		var count func(f *simulate.CallFrame, revertedAbove bool)
		count = func(f *simulate.CallFrame, revertedAbove bool) {
			reverted := revertedAbove || f.Error != ""
			if !reverted {
				wantLogs += len(f.Logs)
				if f.Type == "CREATE" {
					wantCreated++
				}
				wantAddrs[*f.To] = true
			}
			for i := range f.Calls {
				count(&f.Calls[i], reverted)
			}
		}
		count(&root, false)

		a := Build(decoded(alice, &bob), &root)
		if len(a.Logs) != wantLogs || len(a.Created) != wantCreated {
			t.Fatalf("got %d logs and %d created, want %d and %d", len(a.Logs), len(a.Created), wantLogs, wantCreated)
		}
		if a.Reverted != (root.Error != "") {
			t.Fatalf("reverted = %v, root error %q", a.Reverted, root.Error)
		}
		if len(a.Addresses) != len(wantAddrs) {
			t.Fatalf("addresses = %v, want the %d distinct addresses %v", a.Addresses, len(wantAddrs), wantAddrs)
		}
		for _, addr := range a.Addresses {
			if !wantAddrs[addr] {
				t.Fatalf("address %s is not touched by a successful frame", addr)
			}
		}
	})
}
