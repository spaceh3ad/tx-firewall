package chainstate

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

var _ CodeReader = (*ethclient.Client)(nil)

var (
	contract = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	eoa      = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	errNode  = errors.New("node unavailable")
)

// fakeChain answers CodeAt from each address's deployment block.
type fakeChain struct {
	latest   uint64
	deployed map[common.Address]uint64 // address -> block its code appeared in
	oldest   uint64                    // older state is pruned
	err      error

	mu          sync.Mutex
	pastBlocks  []uint64
	codeLookups int
}

func (c *fakeChain) BlockNumber(context.Context) (uint64, error) {
	return c.latest, c.err
}

func (c *fakeChain) CodeAt(_ context.Context, addr common.Address, block *big.Int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codeLookups++
	if c.err != nil {
		return nil, c.err
	}
	at := c.latest
	if block != nil {
		at = block.Uint64()
		c.pastBlocks = append(c.pastBlocks, at)
		if at < c.oldest {
			return nil, errors.New("missing trie node")
		}
	}
	if d, ok := c.deployed[addr]; ok && d <= at {
		return []byte{0x60, 0x80}, nil
	}
	return nil, nil
}

func (c *fakeChain) lookups() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codeLookups
}

func TestStatus(t *testing.T) {
	chain := &fakeChain{latest: 10_000, deployed: map[common.Address]uint64{
		contract: 9_950, // 50 blocks ago
	}}
	cases := map[string]struct {
		window uint64
		addr   common.Address
		want   Status
	}{
		"no code":                  {100, eoa, NoCode},
		"deployed inside window":   {100, contract, Fresh},
		"deployed before window":   {10, contract, Established},
		"deployed exactly at edge": {50, contract, Established}, // had code at latest-50
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := NewRPCFreshness(chain, tc.window, time.Second)
			got, err := f.Status(t.Context(), tc.addr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
			fresh, err := f.IsFreshContract(t.Context(), tc.addr)
			if err != nil || fresh != (tc.want == Fresh) {
				t.Errorf("IsFreshContract = %v, %v", fresh, err)
			}
		})
	}
}

func TestStatusYoungChain(t *testing.T) {
	// On a chain younger than the window, anything deployed after genesis is fresh.
	chain := &fakeChain{latest: 20, deployed: map[common.Address]uint64{contract: 5}}
	got, err := NewRPCFreshness(chain, 7200, time.Second).Status(t.Context(), contract)
	if err != nil || got != Fresh {
		t.Errorf("status = %d, %v, want Fresh", got, err)
	}
	if chain.pastBlocks[0] != 0 {
		t.Errorf("looked back to block %d, want genesis", chain.pastBlocks[0])
	}
}

func TestStatusSkipsHistoryForAddressesWithoutCode(t *testing.T) {
	chain := &fakeChain{latest: 10_000}
	if _, err := NewRPCFreshness(chain, 100, time.Second).Status(t.Context(), eoa); err != nil {
		t.Fatal(err)
	}
	if len(chain.pastBlocks) != 0 {
		t.Errorf("read history for an address without code: %v", chain.pastBlocks)
	}
}

func TestStatusErrors(t *testing.T) {
	cases := map[string]*fakeChain{
		"node down":    {latest: 10_000, err: errNode},
		"state pruned": {latest: 10_000, oldest: 9_990, deployed: map[common.Address]uint64{contract: 1}},
	}
	for name, chain := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRPCFreshness(chain, 100, time.Second).Status(t.Context(), contract); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestVerify(t *testing.T) {
	archive := &fakeChain{latest: 10_000}
	if err := NewRPCFreshness(archive, 7200, time.Second).Verify(t.Context()); err != nil {
		t.Errorf("archive node: unexpected error: %v", err)
	}
	pruned := &fakeChain{latest: 10_000, oldest: 10_000 - 128}
	if err := NewRPCFreshness(pruned, 7200, time.Second).Verify(t.Context()); err == nil {
		t.Error("pruned node with a long window: expected an error")
	}
	if err := NewRPCFreshness(pruned, 100, time.Second).Verify(t.Context()); err != nil {
		t.Errorf("pruned node with a short window: unexpected error: %v", err)
	}
}

// stubStatus returns a fixed status and counts lookups.
type stubStatus struct {
	mu     sync.Mutex
	status map[common.Address]Status
	err    error
	calls  map[common.Address]int
}

func (s *stubStatus) Status(_ context.Context, addr common.Address) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[addr]++
	return s.status[addr], s.err
}

func newStub(status map[common.Address]Status) *stubStatus {
	return &stubStatus{status: status, calls: map[common.Address]int{}}
}

func TestCachedFreshnessCachesOnlyEstablished(t *testing.T) {
	fresh := common.HexToAddress("0x01")
	stub := newStub(map[common.Address]Status{contract: Established, fresh: Fresh, eoa: NoCode})
	c, err := NewCachedFreshness(stub, 10)
	if err != nil {
		t.Fatal(err)
	}

	for range 3 {
		for addr, want := range map[common.Address]bool{contract: false, fresh: true, eoa: false} {
			got, err := c.IsFreshContract(t.Context(), addr)
			if err != nil || got != want {
				t.Fatalf("%s: fresh = %v, %v, want %v", addr, got, err, want)
			}
		}
	}
	if stub.calls[contract] != 1 {
		t.Errorf("established contract looked up %d times, want 1", stub.calls[contract])
	}
	if stub.calls[fresh] != 3 || stub.calls[eoa] != 3 {
		t.Errorf("fresh looked up %d times and no-code %d times, want 3 each", stub.calls[fresh], stub.calls[eoa])
	}
}

// An empty address must not be remembered as "not fresh": an attacker could
// get it cached, then deploy to it (e.g. at a precomputed CREATE2 address).
func TestCachedFreshnessSeesLaterDeployment(t *testing.T) {
	stub := newStub(map[common.Address]Status{contract: NoCode})
	c, _ := NewCachedFreshness(stub, 10)

	if fresh, _ := c.IsFreshContract(t.Context(), contract); fresh {
		t.Fatal("empty address reported fresh")
	}
	stub.status[contract] = Fresh
	if fresh, _ := c.IsFreshContract(t.Context(), contract); !fresh {
		t.Error("contract deployed after a lookup of its empty address was not seen as fresh")
	}
}

func TestCachedFreshnessErrors(t *testing.T) {
	if _, err := NewCachedFreshness(newStub(nil), 0); err == nil {
		t.Error("zero cache size: expected an error")
	}
	stub := newStub(map[common.Address]Status{contract: Established})
	stub.err = errNode
	c, _ := NewCachedFreshness(stub, 10)
	if _, err := c.IsFreshContract(t.Context(), contract); err == nil {
		t.Fatal("expected the lookup error")
	}
	stub.err = nil
	c.IsFreshContract(t.Context(), contract)
	if stub.calls[contract] != 2 {
		t.Errorf("failed lookup was cached")
	}
}

func TestCachedFreshnessStaysBounded(t *testing.T) {
	stub := newStub(map[common.Address]Status{})
	c, _ := NewCachedFreshness(stub, 3)
	for i := range 10 {
		addr := common.BigToAddress(big.NewInt(int64(i + 1)))
		stub.status[addr] = Established
		c.IsFreshContract(t.Context(), addr)
		if len(c.known) > 3 {
			t.Fatalf("cache grew to %d entries, max 3", len(c.known))
		}
	}
}

func TestCachedFreshnessConcurrentUse(t *testing.T) {
	chain := &fakeChain{latest: 10_000, deployed: map[common.Address]uint64{contract: 1}}
	c, _ := NewCachedFreshness(NewRPCFreshness(chain, 100, time.Second), 2)
	if _, err := c.IsFreshContract(t.Context(), contract); err != nil { // warm the cache
		t.Fatal(err)
	}
	warm := chain.lookups()

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if fresh, err := c.IsFreshContract(context.Background(), contract); err != nil || fresh {
				t.Errorf("fresh = %v, err = %v", fresh, err)
			}
		})
	}
	wg.Wait()
	if extra := chain.lookups() - warm; extra != 0 {
		t.Errorf("cached established contract caused %d more node lookups", extra)
	}
}

// Reference model over arbitrary chains: fresh exactly when the address has
// code now and had none window blocks ago, and the cache never changes the answer.
func FuzzFreshness(f *testing.F) {
	f.Add(uint64(10_000), uint64(9_950), true, uint64(100))
	f.Add(uint64(20), uint64(5), true, uint64(7200))
	f.Add(uint64(0), uint64(0), true, uint64(0))
	f.Add(uint64(500), uint64(0), false, uint64(1))

	f.Fuzz(func(t *testing.T, latest, deployedAt uint64, hasCode bool, window uint64) {
		deployedAt = min(deployedAt, latest)
		chain := &fakeChain{latest: latest, deployed: map[common.Address]uint64{}}
		if hasCode {
			chain.deployed[contract] = deployedAt
		}

		var past uint64
		if latest >= window {
			past = latest - window
		}
		want := hasCode && deployedAt > past

		rpc := NewRPCFreshness(chain, window, time.Second)
		got, err := rpc.IsFreshContract(t.Context(), contract)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("fresh = %v, want %v (latest %d, deployed %d, window %d)", got, want, latest, deployedAt, window)
		}

		cached, _ := NewCachedFreshness(rpc, 4)
		for range 2 {
			if got, err := cached.IsFreshContract(t.Context(), contract); err != nil || got != want {
				t.Fatalf("cached fresh = %v, %v, want %v", got, err, want)
			}
		}
	})
}
