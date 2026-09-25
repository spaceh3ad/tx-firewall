package sanctions

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// mutableChecker answers from a set that tests can change, counting lookups per address.
type mutableChecker struct {
	mu         sync.Mutex
	sanctioned map[common.Address]bool
	failing    bool
	calls      map[common.Address]int
}

func newMutableChecker() *mutableChecker {
	return &mutableChecker{sanctioned: map[common.Address]bool{}, calls: map[common.Address]int{}}
}

func (m *mutableChecker) IsSanctioned(_ context.Context, addr common.Address) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[addr]++
	if m.failing {
		return false, errBackend
	}
	return m.sanctioned[addr], nil
}

// fakeClock is a manually advanced clock for the cache.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(next Checker, ttl time.Duration, maxEntries int) (*CachedChecker, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := NewCachedChecker(next, ttl, maxEntries)
	c.now = clock.now
	return c, clock
}

func TestCachedCheckerServesFromCacheUntilExpiry(t *testing.T) {
	backend := newMutableChecker()
	backend.sanctioned[alice] = true
	c, clock := newTestCache(backend, time.Minute, 100)

	for range 3 {
		if !isSanctioned(t, c, alice) {
			t.Fatal("sanctioned address reported clean")
		}
	}
	if backend.calls[alice] != 1 {
		t.Errorf("backend called %d times within ttl, want 1", backend.calls[alice])
	}

	// Delisted upstream: the cached answer stays until it expires.
	backend.sanctioned[alice] = false
	clock.advance(time.Minute - time.Second)
	if !isSanctioned(t, c, alice) {
		t.Error("answer changed before ttl expired")
	}
	clock.advance(time.Second)
	if isSanctioned(t, c, alice) {
		t.Error("expired answer still served")
	}
	if backend.calls[alice] != 2 {
		t.Errorf("backend called %d times, want 2", backend.calls[alice])
	}
}

func TestCachedCheckerCachesCleanAnswers(t *testing.T) {
	backend := newMutableChecker()
	c, _ := newTestCache(backend, time.Minute, 100)

	isSanctioned(t, c, bob)
	isSanctioned(t, c, bob)
	if backend.calls[bob] != 1 {
		t.Errorf("backend called %d times, want 1", backend.calls[bob])
	}
}

func TestCachedCheckerDoesNotCacheErrors(t *testing.T) {
	backend := newMutableChecker()
	backend.failing = true
	c, _ := newTestCache(backend, time.Minute, 100)

	if _, err := c.IsSanctioned(t.Context(), alice); err == nil {
		t.Fatal("expected the backend error")
	}
	backend.failing = false
	backend.sanctioned[alice] = true
	if !isSanctioned(t, c, alice) {
		t.Error("failed lookup was cached instead of retried")
	}
}

func TestCachedCheckerStaysBounded(t *testing.T) {
	backend := newMutableChecker()
	c, clock := newTestCache(backend, time.Minute, 3)

	for i := range 10 {
		isSanctioned(t, c, common.BigToAddress(big.NewInt(int64(i+1))))
		clock.advance(time.Second)
		if len(c.entries) > 3 {
			t.Fatalf("cache grew to %d entries, max 3", len(c.entries))
		}
	}
}

func TestCachedCheckerEvictsExpiredFirst(t *testing.T) {
	backend := newMutableChecker()
	c, clock := newTestCache(backend, time.Minute, 2)

	isSanctioned(t, c, alice)
	clock.advance(2 * time.Minute) // alice expires
	isSanctioned(t, c, bob)
	isSanctioned(t, c, carol) // full: evicting expired alice makes room, bob survives

	isSanctioned(t, c, bob)
	if backend.calls[bob] != 1 {
		t.Errorf("fresh entry was evicted: backend called %d times for bob, want 1", backend.calls[bob])
	}
}

func TestCachedCheckerConcurrentUse(t *testing.T) {
	backend := newMutableChecker()
	backend.sanctioned[alice] = true
	c := NewCachedChecker(backend, time.Minute, 2)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			addr := []common.Address{alice, bob, carol}[i%3]
			hit, err := c.IsSanctioned(context.Background(), addr)
			if err != nil || hit != (addr == alice) {
				t.Errorf("%s: hit=%v err=%v", addr, hit, err)
			}
		})
	}
	wg.Wait()
}

// Model-based check: the cache must return exactly what the backend said at
// its last lookup of that address while that answer is younger than ttl,
// and must ask the backend again once it is not.
func FuzzCachedChecker(f *testing.F) {
	f.Add([]byte{0x00, 0x41, 0x80, 0x01, 0xc0, 0x00})
	f.Add([]byte{0x03, 0x03, 0xff, 0x03})

	const ttl = 10 * time.Second
	addrs := []common.Address{alice, bob, carol, common.HexToAddress("0x01")}

	f.Fuzz(func(t *testing.T, ops []byte) {
		backend := newMutableChecker()
		c, clock := newTestCache(backend, ttl, len(addrs)) // never full, so no eviction

		type seen struct {
			answer bool
			at     time.Time
		}
		model := map[common.Address]seen{}

		for _, op := range ops {
			addr := addrs[op&0x03]
			switch op >> 6 {
			case 0: // look up
				callsBefore := backend.calls[addr]
				got := isSanctioned(t, c, addr)

				last, ok := model[addr]
				if ok && clock.now().Sub(last.at) < ttl {
					if got != last.answer || backend.calls[addr] != callsBefore {
						t.Fatalf("%s: fresh cached answer not served", addr)
					}
					continue
				}
				if backend.calls[addr] != callsBefore+1 {
					t.Fatalf("%s: stale or missing entry did not query the backend", addr)
				}
				if got != backend.sanctioned[addr] {
					t.Fatalf("%s: got %v, backend says %v", addr, got, backend.sanctioned[addr])
				}
				model[addr] = seen{answer: got, at: clock.now()}
			case 1: // flip the backend's answer
				backend.sanctioned[addr] = !backend.sanctioned[addr]
			default: // advance time by 0..15s
				clock.advance(time.Duration(op&0x0f) * time.Second)
			}
		}
	})
}
