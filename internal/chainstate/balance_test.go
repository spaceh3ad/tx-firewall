package chainstate

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

var _ BalanceClient = (*ethclient.Client)(nil)

var token = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")

// fakeBalances plays a node holding ETH and token balances.
type fakeBalances struct {
	eth      map[common.Address]*big.Int
	tokens   map[common.Address]map[common.Address]*big.Int
	response []byte // overrides the balanceOf answer when set
	callErr  error
	balErr   error

	lastMsg ethereum.CallMsg
}

func (f *fakeBalances) BalanceAt(_ context.Context, account common.Address, _ *big.Int) (*big.Int, error) {
	if f.balErr != nil {
		return nil, f.balErr
	}
	if b, ok := f.eth[account]; ok {
		return b, nil
	}
	return new(big.Int), nil
}

func (f *fakeBalances) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	f.lastMsg = msg
	if f.callErr != nil {
		return nil, f.callErr
	}
	if f.response != nil {
		return f.response, nil
	}
	holder := common.BytesToAddress(msg.Data[4:])
	bal := new(big.Int)
	if b, ok := f.tokens[*msg.To][holder]; ok {
		bal = b
	}
	return common.BigToHash(bal).Bytes(), nil
}

func TestBalance(t *testing.T) {
	node := &fakeBalances{
		eth:    map[common.Address]*big.Int{contract: big.NewInt(5)},
		tokens: map[common.Address]map[common.Address]*big.Int{token: {contract: big.NewInt(1_000)}},
	}
	b := NewRPCBalances(node, time.Second)

	eth, ok, err := b.Balance(t.Context(), common.Address{}, contract)
	if err != nil || !ok || eth.Int64() != 5 {
		t.Errorf("ETH balance = %v, %v, %v; want 5", eth, ok, err)
	}
	bal, ok, err := b.Balance(t.Context(), token, contract)
	if err != nil || !ok || bal.Int64() != 1_000 {
		t.Errorf("token balance = %v, %v, %v; want 1000", bal, ok, err)
	}
	if !bytes.Equal(node.lastMsg.Data[:4], []byte{0x70, 0xa0, 0x82, 0x31}) || *node.lastMsg.To != token {
		t.Errorf("called %x on %s, want balanceOf on the token", node.lastMsg.Data[:4], node.lastMsg.To)
	}
}

func TestBalanceUnmeasurableToken(t *testing.T) {
	cases := map[string]*fakeBalances{
		"empty response (no code)": {response: []byte{}},
		"short response":           {response: make([]byte, 31)},
		"long response":            {response: make([]byte, 64)},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			bal, ok, err := NewRPCBalances(node, time.Second).Balance(t.Context(), token, contract)
			if err != nil || ok || bal != nil {
				t.Errorf("got %v, %v, %v; want not ok and no error", bal, ok, err)
			}
		})
	}
}

func TestBalanceErrors(t *testing.T) {
	cases := map[string]struct {
		node  *fakeBalances
		asset common.Address
	}{
		"ETH balance, node down":   {&fakeBalances{balErr: errNode}, common.Address{}},
		"token balance, node down": {&fakeBalances{callErr: errNode}, token},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NewRPCBalances(tc.node, time.Second).Balance(t.Context(), tc.asset, contract); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// Through a real RPC client: a reverting balanceOf comes back as a JSON-RPC
// error, which means "can't measure", while a dead node is an error.
func TestBalanceRevertOverRPC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":3,"message":"execution reverted","data":"0x"}}`))
	}))
	defer srv.Close()
	client, err := rpc.DialContext(t.Context(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	bal, ok, err := NewRPCBalances(ethclient.NewClient(client), time.Second).Balance(t.Context(), token, contract)
	if err != nil || ok || bal != nil {
		t.Errorf("reverting balanceOf: got %v, %v, %v; want not ok and no error", bal, ok, err)
	}

	srv.Close()
	if _, _, err := NewRPCBalances(ethclient.NewClient(client), time.Second).Balance(t.Context(), token, contract); err == nil {
		t.Error("dead node: expected an error")
	}
}

// Any balanceOf response is handled without panicking: exactly 32 bytes decode
// as the balance, anything else is "can't measure".
func FuzzBalanceResponse(f *testing.F) {
	f.Add(common.BigToHash(big.NewInt(7)).Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, 33))

	f.Fuzz(func(t *testing.T, response []byte) {
		node := &fakeBalances{response: response}
		bal, ok, err := NewRPCBalances(node, time.Second).Balance(t.Context(), token, contract)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok != (len(response) == 32) {
			t.Fatalf("ok = %v for a %d-byte response", ok, len(response))
		}
		if ok && bal.Cmp(new(big.Int).SetBytes(response)) != 0 {
			t.Fatalf("balance = %s, want %x", bal, response)
		}
	})
}
