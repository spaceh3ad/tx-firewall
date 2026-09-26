package analysis

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spaceh3ad/tx-firewall/internal/events"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
)

var transferTopic = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))

func erc20Log(token, from, to common.Address, amount int64) simulate.Log {
	return simulate.Log{
		Address: token,
		Topics:  []common.Hash{transferTopic, common.BytesToHash(from.Bytes()), common.BytesToHash(to.Bytes())},
		Data:    common.BigToHash(big.NewInt(amount)).Bytes(),
	}
}

func findFlow(flows []Flow, asset, holder common.Address) (Flow, bool) {
	for _, f := range flows {
		if f.Asset == asset && f.Holder == holder {
			return f, true
		}
	}
	return Flow{}, false
}

func TestBuildFlows(t *testing.T) {
	token := common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	vault := common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")
	nftTokenID := common.BigToHash(big.NewInt(7))

	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(proxy), Value: (*hexutil.Big)(big.NewInt(10)),
		Calls: []simulate.CallFrame{
			// vault sends 100 tokens to carol and gets 30 back
			{Type: "CALL", From: proxy, To: addrPtr(token), Logs: []simulate.Log{
				erc20Log(token, vault, carol, 100),
				erc20Log(token, carol, vault, 30),
				erc20Log(token, bob, bob, 999), // self transfer: moves nothing
				{Address: token, Topics: []common.Hash{transferTopic, common.BytesToHash(vault.Bytes()), common.BytesToHash(carol.Bytes()), nftTokenID}},
			}},
			// proxy forwards 4 wei to bob; delegatecall "value" moves nothing
			{Type: "CALL", From: proxy, To: addrPtr(bob), Value: (*hexutil.Big)(big.NewInt(4))},
			{Type: "DELEGATECALL", From: proxy, To: addrPtr(newImpl), Value: (*hexutil.Big)(big.NewInt(10))},
			// a reverted payment never happens
			{Type: "CALL", From: proxy, To: addrPtr(carol), Value: (*hexutil.Big)(big.NewInt(6)), Error: "execution reverted"},
		},
	}
	a := Build(decoded(alice, &proxy), trace)

	cases := []struct {
		asset, holder common.Address
		out, in       int64
	}{
		{token, vault, 100, 30},
		{token, carol, 30, 100},
		{ETH, alice, 10, 0},
		{ETH, proxy, 4, 10},
		{ETH, bob, 0, 4},
	}
	for _, c := range cases {
		f, ok := findFlow(a.Flows, c.asset, c.holder)
		if !ok {
			t.Errorf("no flow of %s for %s", c.asset, c.holder)
			continue
		}
		if f.Out.Int64() != c.out || f.In.Int64() != c.in {
			t.Errorf("%s of %s: out %s in %s, want out %d in %d", c.holder, c.asset, f.Out, f.In, c.out, c.in)
		}
	}
	if f, _ := findFlow(a.Flows, token, vault); f.NetOut().Int64() != 70 {
		t.Errorf("vault net outflow = %s, want 70", f.NetOut())
	}
	for _, missing := range []struct{ asset, holder common.Address }{{token, bob}, {ETH, newImpl}, {ETH, carol}} {
		if f, ok := findFlow(a.Flows, missing.asset, missing.holder); ok {
			t.Errorf("unexpected flow %+v", f)
		}
	}
}

func TestBuildFlowsSelfdestruct(t *testing.T) {
	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(proxy),
		Calls: []simulate.CallFrame{{Type: "SELFDESTRUCT", From: proxy, To: addrPtr(carol), Value: (*hexutil.Big)(big.NewInt(50))}},
	}
	a := Build(decoded(alice, &proxy), trace)
	if f, ok := findFlow(a.Flows, ETH, proxy); !ok || f.Out.Int64() != 50 {
		t.Errorf("selfdestruct sweep not counted: %+v", a.Flows)
	}
}

// Conservation: for every asset, the total sent equals the total received,
// and both equal the sum of the non-self transfers that went in.
func FuzzComputeFlows(f *testing.F) {
	f.Add([]byte{0x01, 0x12, 0x21})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x93, 0x39, 0xff})

	holders := []common.Address{alice, bob, carol, proxy}
	tokens := []common.Address{common.HexToAddress("0x01"), common.HexToAddress("0x02")}

	f.Fuzz(func(t *testing.T, data []byte) {
		var frames []Frame
		var transfers []events.Transfer
		want := map[common.Address]*big.Int{}
		for i, b := range data {
			from, to := holders[b&0x03], holders[(b>>2)&0x03]
			amount := big.NewInt(int64(i+1) * int64(b))
			asset := ETH
			if b&0x80 != 0 {
				asset = tokens[(b>>4)&0x01]
				transfers = append(transfers, events.Transfer{Standard: events.ERC20, Token: asset, From: from, To: to, Amount: amount})
			} else {
				frames = append(frames, Frame{Type: "CALL", From: from, To: to, Value: amount})
			}
			if from != to {
				if want[asset] == nil {
					want[asset] = new(big.Int)
				}
				want[asset].Add(want[asset], amount)
			}
		}

		out, in := map[common.Address]*big.Int{}, map[common.Address]*big.Int{}
		for _, fl := range computeFlows(frames, transfers) {
			if out[fl.Asset] == nil {
				out[fl.Asset], in[fl.Asset] = new(big.Int), new(big.Int)
			}
			out[fl.Asset].Add(out[fl.Asset], fl.Out)
			in[fl.Asset].Add(in[fl.Asset], fl.In)
		}
		for asset, total := range want {
			if out[asset] == nil || out[asset].Cmp(total) != 0 || in[asset].Cmp(total) != 0 {
				t.Fatalf("asset %s: out %v in %v, want %s both", asset, out[asset], in[asset], total)
			}
		}
		for asset := range out {
			if want[asset] == nil && (out[asset].Sign() != 0 || in[asset].Sign() != 0) {
				t.Fatalf("asset %s moved without any transfer", asset)
			}
		}
	})
}
