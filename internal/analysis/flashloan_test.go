package analysis

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spaceh3ad/tx-firewall/internal/events"
	"github.com/spaceh3ad/tx-firewall/internal/simulate"
)

var (
	weth = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
	usdc = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	pool = common.HexToAddress("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")
)

func tr(token, from, to common.Address, amount int64) events.Transfer {
	return events.Transfer{Standard: events.ERC20, Token: token, From: from, To: to, Amount: big.NewInt(amount)}
}

func TestFindRepaidLoans(t *testing.T) {
	cases := map[string]struct {
		transfers []events.Transfer
		want      []FlashLoan
	}{
		"borrowed and repaid with fee": {
			[]events.Transfer{tr(weth, pool, alice, 100), tr(weth, alice, carol, 5), tr(weth, alice, pool, 101)},
			[]FlashLoan{{Lender: pool, Token: weth, Amount: big.NewInt(100), Source: RepaidPattern}},
		},
		"repaid in two parts": {
			[]events.Transfer{tr(weth, pool, alice, 100), tr(weth, alice, pool, 60), tr(weth, bob, pool, 40)},
			[]FlashLoan{{Lender: pool, Token: weth, Amount: big.NewInt(100), Source: RepaidPattern}},
		},
		"not fully repaid (a swap or a drain)": {
			[]events.Transfer{tr(weth, pool, alice, 100), tr(weth, alice, pool, 99)},
			nil,
		},
		"repaid in a different token": {
			[]events.Transfer{tr(weth, pool, alice, 100), tr(usdc, alice, pool, 100_000)},
			nil,
		},
		"a deposit returned in full matches from the depositor's side": {
			[]events.Transfer{tr(weth, alice, pool, 100), tr(weth, pool, alice, 100)},
			// alice sent 100 and got it all back later: the pattern, with alice as lender
			[]FlashLoan{{Lender: alice, Token: weth, Amount: big.NewInt(100), Source: RepaidPattern}},
		},
		"mint and burn are not loans": {
			[]events.Transfer{tr(weth, common.Address{}, alice, 100), tr(weth, alice, common.Address{}, 100)},
			nil,
		},
		"same lender and token reported once": {
			[]events.Transfer{tr(weth, pool, alice, 100), tr(weth, alice, pool, 100), tr(weth, pool, alice, 50), tr(weth, alice, pool, 50)},
			[]FlashLoan{{Lender: pool, Token: weth, Amount: big.NewInt(100), Source: RepaidPattern}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := findRepaidLoans(tc.transfers)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i].Lender != tc.want[i].Lender || got[i].Token != tc.want[i].Token ||
					got[i].Amount.Cmp(tc.want[i].Amount) != 0 || got[i].Source != tc.want[i].Source {
					t.Errorf("loan %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestBuildFlashLoans(t *testing.T) {
	balancerVault := common.HexToAddress("0xBA12222222228d8Ba445958a75a0704d566BF2C8")
	balancerTopic := crypto.Keccak256Hash([]byte("FlashLoan(address,address,uint256,uint256)"))
	announcement := simulate.Log{
		Address: balancerVault,
		Topics:  []common.Hash{balancerTopic, common.BytesToHash(alice.Bytes()), common.BytesToHash(weth.Bytes())},
		Data:    append(common.BigToHash(big.NewInt(100)).Bytes(), make([]byte, 32)...),
	}
	trace := &simulate.CallFrame{
		Type: "CALL", From: alice, To: addrPtr(balancerVault),
		Logs: []simulate.Log{announcement},
		Calls: []simulate.CallFrame{
			// the vault's own transfers also match the pattern; the event already covers them
			{Type: "CALL", From: balancerVault, To: addrPtr(weth), Logs: []simulate.Log{erc20Log(weth, balancerVault, alice, 100)}},
			{Type: "CALL", From: alice, To: addrPtr(weth), Logs: []simulate.Log{erc20Log(weth, alice, balancerVault, 100)}},
			// an unrelated pool lends in the same transaction without an event
			{Type: "CALL", From: alice, To: addrPtr(usdc), Logs: []simulate.Log{
				erc20Log(usdc, pool, alice, 7), erc20Log(usdc, alice, pool, 7),
			}},
		},
	}
	a := Build(decoded(alice, &balancerVault), trace)

	if len(a.FlashLoans) != 2 {
		t.Fatalf("flash loans = %+v, want the Balancer event and the pool pattern", a.FlashLoans)
	}
	if l := a.FlashLoans[0]; l.Source != "Balancer V2" || l.Lender != balancerVault || l.Token != weth || l.Amount.Int64() != 100 {
		t.Errorf("first loan = %+v", l)
	}
	if l := a.FlashLoans[1]; l.Source != RepaidPattern || l.Lender != pool || l.Token != usdc {
		t.Errorf("second loan = %+v", l)
	}
}

// Reference model: a (lender, token) pair is reported exactly when some
// transfer out of the lender is followed by at least as much coming back,
// excluding the zero address and self transfers; and never twice.
func FuzzFindRepaidLoans(f *testing.F) {
	f.Add([]byte{0x04, 0x01})
	f.Add([]byte{0x04, 0x41, 0x81})
	f.Add([]byte{0x1c, 0x13, 0x00})

	parties := []common.Address{{}, alice, bob, pool}
	tokens := []common.Address{weth, usdc}

	f.Fuzz(func(t *testing.T, data []byte) {
		var transfers []events.Transfer
		for i, b := range data {
			transfers = append(transfers, tr(tokens[(b>>4)&0x01], parties[b&0x03], parties[(b>>2)&0x03], int64(i%3+1)*int64(b>>6+1)))
		}

		type key struct{ lender, token common.Address }
		want := map[key]bool{}
		for i, out := range transfers {
			if out.From == (common.Address{}) || out.From == out.To {
				continue
			}
			back := new(big.Int)
			for _, in := range transfers[i+1:] {
				if in.Token == out.Token && in.To == out.From && in.From != out.From {
					back.Add(back, in.Amount)
				}
			}
			if back.Cmp(out.Amount) >= 0 {
				want[key{out.From, out.Token}] = true
			}
		}

		got := map[key]bool{}
		for _, l := range findRepaidLoans(transfers) {
			k := key{l.Lender, l.Token}
			if got[k] {
				t.Fatalf("pair %v reported twice", k)
			}
			got[k] = true
		}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("missing %v; got %v", k, got)
			}
		}
	})
}
