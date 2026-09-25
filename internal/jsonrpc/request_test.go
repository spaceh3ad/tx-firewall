package jsonrpc

import "testing"

func TestParseSingleRequest(t *testing.T) {
	reqs, err := ParseRequests([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reqs) != 1 || reqs[0].Method != "eth_chainId" {
		t.Fatalf("unexpected result: %+v", reqs)
	}
}

func TestParseBatch(t *testing.T) {
	reqs, err := ParseRequests([]byte(`[{"method":"eth_chainId"},{"method":"eth_sendRawTransaction","params":["0x00"]}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reqs) != 2 || reqs[1].Method != "eth_sendRawTransaction" {
		t.Fatalf("unexpected result: %+v", reqs)
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	for _, body := range []string{"", "   ", "[]", "not json", `{"method":`} {
		if _, err := ParseRequests([]byte(body)); err == nil {
			t.Errorf("expected error for body %q", body)
		}
	}
}
