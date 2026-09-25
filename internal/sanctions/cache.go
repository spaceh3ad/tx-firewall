package sanctions

import (
	"context"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// CachedChecker remembers answers from a slower checker (such as the oracle)
// for ttl. A newly sanctioned address can therefore pass for up to ttl.
// Errors are never cached, so a failed lookup is retried on the next call.
type CachedChecker struct {
	next       Checker
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	mu      sync.Mutex
	entries map[common.Address]cacheEntry
}

type cacheEntry struct {
	sanctioned bool
	expires    time.Time
}

var _ Checker = (*CachedChecker)(nil)

// NewCachedChecker caches up to maxEntries answers from next.
func NewCachedChecker(next Checker, ttl time.Duration, maxEntries int) *CachedChecker {
	return &CachedChecker{
		next:       next,
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
		entries:    make(map[common.Address]cacheEntry),
	}
}

func (c *CachedChecker) IsSanctioned(ctx context.Context, addr common.Address) (bool, error) {
	now := c.now()

	c.mu.Lock()
	e, ok := c.entries[addr]
	c.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.sanctioned, nil
	}

	// The lock is not held during the lookup, so concurrent misses for the
	// same address may both query next; that only costs an extra call.
	hit, err := c.next.IsSanctioned(ctx, addr)
	if err != nil {
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		c.evict(now)
	}
	c.entries[addr] = cacheEntry{sanctioned: hit, expires: now.Add(c.ttl)}
	return hit, nil
}

// evict drops expired entries, or everything if the cache is still full,
// which keeps memory bounded without tracking access order.
func (c *CachedChecker) evict(now time.Time) {
	for addr, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, addr)
		}
	}
	if len(c.entries) >= c.maxEntries {
		clear(c.entries)
	}
}
