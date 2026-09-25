package sanctions

import (
	"bytes"
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

var _ ContractCaller = (*ethclient.Client)(nil)

// fakeCaller plays the oracle contract: addresses in sanctioned return true.
type fakeCaller struct {
	sanctioned map[common.Address]bool
	code       []byte
	err        error
	response   []byte // overrides the encoded answer when set

	lastMsg         ethereum.CallMsg
	lastHadDeadline bool
}

func (f *fakeCaller) CallContract(ctx context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	f.lastMsg = msg
	_, f.lastHadDeadline = ctx.Deadline()
	if f.err != nil {
		return nil, f.err
	}
	if f.response != nil {
		return f.response, nil
	}
	out := make([]byte, 32)
	if f.sanctioned[common.BytesToAddress(msg.Data[4:])] {
		out[31] = 1
	}
	return out, nil
}

func (f *fakeCaller) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return f.code, f.err
}

func encodedBool(v bool) []byte {
	out := make([]byte, 32)
	if v {
		out[31] = 1
	}
	return out
}

func TestIsSanctionedSelector(t *testing.T) {
	if got := hexutil.Encode(isSanctionedSelector); got != "0xdf592f7d" {
		t.Errorf("selector = %s, want 0xdf592f7d", got)
	}
}

func TestOracleChecker(t *testing.T) {
	caller := &fakeCaller{sanctioned: map[common.Address]bool{alice: true}}
	c := NewOracleChecker(caller, ChainalysisOracle, time.Second)

	if !isSanctioned(t, c, alice) {
		t.Error("sanctioned address reported clean")
	}
	if isSanctioned(t, c, bob) {
		t.Error("clean address reported sanctioned")
	}

	if caller.lastMsg.To == nil || *caller.lastMsg.To != ChainalysisOracle {
		t.Errorf("called %v, want the oracle %s", caller.lastMsg.To, ChainalysisOracle)
	}
	if !caller.lastHadDeadline {
		t.Error("oracle call has no timeout")
	}
}

func TestOracleCheckerFailsClosed(t *testing.T) {
	cases := map[string]*fakeCaller{
		"rpc error":           {err: errBackend},
		"empty response":      {response: []byte{}}, // what an address without code returns
		"short response":      {response: make([]byte, 31)},
		"long response":       {response: make([]byte, 64)},
		"not a bool":          {response: append(make([]byte, 31), 2)},
		"garbage upper bytes": {response: append([]byte{1}, make([]byte, 31)...)},
	}
	for name, caller := range cases {
		t.Run(name, func(t *testing.T) {
			hit, err := NewOracleChecker(caller, ChainalysisOracle, time.Second).IsSanctioned(t.Context(), alice)
			if err == nil {
				t.Fatal("expected an error")
			}
			if hit {
				t.Error("an error must never report a hit")
			}
		})
	}
}

func TestOracleCheckerVerify(t *testing.T) {
	cases := map[string]struct {
		caller  *fakeCaller
		wantErr bool
	}{
		"contract deployed": {&fakeCaller{code: []byte{0x60, 0x80}}, false},
		"no contract":       {&fakeCaller{}, true},
		"rpc error":         {&fakeCaller{err: errBackend}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := NewOracleChecker(tc.caller, ChainalysisOracle, time.Second).Verify(t.Context())
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// For any address, the calldata is the selector followed by the address left-padded to 32 bytes.
func FuzzIsSanctionedCalldata(f *testing.F) {
	f.Add(alice.Bytes())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		addr := common.BytesToAddress(raw)
		data := isSanctionedCalldata(addr)

		if len(data) != 36 {
			t.Fatalf("calldata length = %d, want 36", len(data))
		}
		if !bytes.Equal(data[:4], isSanctionedSelector) {
			t.Fatalf("calldata starts with %x, want the selector", data[:4])
		}
		if !bytes.Equal(data[4:16], make([]byte, 12)) || common.BytesToAddress(data[16:]) != addr {
			t.Fatalf("argument %x does not encode %s", data[4:], addr)
		}
	})
}

// Any response decodes without panicking; only the two canonical encodings are accepted.
func FuzzDecodeBool(f *testing.F) {
	f.Add(encodedBool(true))
	f.Add(encodedBool(false))
	f.Add([]byte{})
	f.Add(append(make([]byte, 31), 2))

	f.Fuzz(func(t *testing.T, out []byte) {
		got, err := decodeBool(out)
		switch {
		case bytes.Equal(out, encodedBool(true)):
			if err != nil || !got {
				t.Fatalf("canonical true decoded as %v, %v", got, err)
			}
		case bytes.Equal(out, encodedBool(false)):
			if err != nil || got {
				t.Fatalf("canonical false decoded as %v, %v", got, err)
			}
		default:
			if err == nil {
				t.Fatalf("non-canonical response %x accepted as %v", out, got)
			}
		}
	})
}
