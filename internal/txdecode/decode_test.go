package txdecode

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Anvil's default account (0): a well-known test key, never use it for real funds.
const anvilKey0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// signedParams builds eth_sendRawTransaction params for a signed EIP-1559 transfer.
func signedParams(t *testing.T) (json.RawMessage, common.Address, common.Hash) {
	t.Helper()

	key, err := crypto.HexToECDSA(anvilKey0)
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(31337)
	to := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(chainID), &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(1e18),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal([]string{hexutil.Encode(raw)})
	return params, crypto.PubkeyToAddress(key.PublicKey), tx.Hash()
}

func TestDecodeRecoversSender(t *testing.T) {
	params, wantFrom, wantHash := signedParams(t)

	decoded, err := DecodeRawTransaction(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.From != wantFrom {
		t.Errorf("from = %s, want %s", decoded.From, wantFrom)
	}
	if decoded.Tx.Hash() != wantHash {
		t.Errorf("hash = %s, want %s", decoded.Tx.Hash(), wantHash)
	}
}

func TestDecodeRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"not an array":   `"0x00"`,
		"no params":      `[]`,
		"too many":       `["0x00","0x01"]`,
		"bad hex":        `["0xzz"]`,
		"missing prefix": `["02f870"]`,
		"garbage tx":     `["0xdeadbeef"]`,
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRawTransaction(json.RawMessage(params)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
