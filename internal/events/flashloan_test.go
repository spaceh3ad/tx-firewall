package events

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Checked against `cast keccak "<signature>"` and the protocols' published topics.
var (
	topicAaveV3FlashLoan     = common.HexToHash("0xefefaba5e921573100900a3ad9cf29f222d995fb3b6045797eaea7521bd8d6f0")
	topicBalancerV2FlashLoan = common.HexToHash("0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0")
	topicUniswapV3Flash      = common.HexToHash("0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633")
)

func amountWord(v int64) common.Hash { return common.BigToHash(big.NewInt(v)) }

func TestDecodeFlashLoan(t *testing.T) {
	pool := common.HexToAddress("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
	cases := map[string]struct {
		topics     []common.Hash
		data       []byte
		protocol   string
		wantToken  common.Address
		wantAmount int64 // -1: unknown
	}{
		"Aave V3": {
			[]common.Hash{topicAaveV3FlashLoan, word(alice), word(token), amountWord(0)},
			data(word(alice), amountWord(1_000), amountWord(0), amountWord(5)),
			"Aave V3", token, 1_000,
		},
		"Balancer V2": {
			[]common.Hash{topicBalancerV2FlashLoan, word(alice), word(token)},
			data(amountWord(2_000), amountWord(0)),
			"Balancer V2", token, 2_000,
		},
		"Uniswap V3": {
			[]common.Hash{topicUniswapV3Flash, word(alice), word(bob)},
			data(amountWord(1), amountWord(2), amountWord(3), amountWord(4)),
			"Uniswap V3", common.Address{}, -1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := DecodeFlashLoan(pool, tc.topics, tc.data)
			if !ok {
				t.Fatal("flash loan not recognised")
			}
			if got.Protocol != tc.protocol || got.Lender != pool || got.Token != tc.wantToken {
				t.Errorf("got %+v", got)
			}
			if tc.wantAmount < 0 {
				if got.Amount != nil {
					t.Errorf("amount = %s, want unknown", got.Amount)
				}
			} else if got.Amount == nil || got.Amount.Int64() != tc.wantAmount {
				t.Errorf("amount = %v, want %d", got.Amount, tc.wantAmount)
			}
		})
	}
}

func TestDecodeFlashLoanIgnoresOtherLogs(t *testing.T) {
	cases := map[string]struct {
		topics []common.Hash
		data   []byte
	}{
		"no topics":           {nil, nil},
		"Transfer":            {[]common.Hash{topicTransfer, word(alice), word(bob)}, data(amountWord(1))},
		"Aave, short data":    {[]common.Hash{topicAaveV3FlashLoan, word(alice), word(token), amountWord(0)}, data(amountWord(1))},
		"Balancer, 4 topics":  {[]common.Hash{topicBalancerV2FlashLoan, word(alice), word(token), {}}, data(amountWord(1), amountWord(0))},
		"Uniswap, short data": {[]common.Hash{topicUniswapV3Flash, word(alice), word(bob)}, data(amountWord(1))},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := DecodeFlashLoan(token, tc.topics, tc.data); ok {
				t.Errorf("decoded %+v", got)
			}
		})
	}
}

// Any log decodes without panicking, and a decoded event always matches its
// protocol's exact topic count and data length.
func FuzzDecodeFlashLoan(f *testing.F) {
	f.Add(uint8(0), uint8(3), make([]byte, 128))
	f.Add(uint8(1), uint8(2), make([]byte, 64))
	f.Add(uint8(2), uint8(2), make([]byte, 128))
	f.Add(uint8(3), uint8(0), []byte{})

	topic0s := []common.Hash{topicAaveV3FlashLoan, topicBalancerV2FlashLoan, topicUniswapV3Flash, topicTransfer}
	shapes := map[common.Hash][2]int{ // topics, data bytes
		topicAaveV3FlashLoan:     {4, 128},
		topicBalancerV2FlashLoan: {3, 64},
		topicUniswapV3Flash:      {3, 128},
	}

	f.Fuzz(func(t *testing.T, which, nIndexed uint8, raw []byte) {
		topics := []common.Hash{topic0s[int(which)%len(topic0s)]}
		for range int(nIndexed % 5) {
			topics = append(topics, common.BytesToHash(raw))
		}
		got, ok := DecodeFlashLoan(token, topics, raw)
		if !ok {
			return
		}
		shape, known := shapes[topics[0]]
		if !known || len(topics) != shape[0] || len(raw) != shape[1] || got.Lender != token {
			t.Fatalf("decoded %+v from %d topics and %d data bytes", got, len(topics), len(raw))
		}
	})
}
