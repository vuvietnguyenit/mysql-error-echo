package main

import (
	"testing"
	"time"
)

const IPToTest = "10.196.6.35"

func TestReverseLookupCaching(t *testing.T) {
	r := NewResolver("", true, 10, 5)
	defer r.StopCacheCleaner()

	ip := IPToTest

	names := r.ReverseLookup(ip)

	if len(names) == 0 {
		t.Errorf("expected at least one domain, got none")
	}
	t.Log("Domain resolved: ", names)

	// Check if cached
	r.Caching.mu.RLock()
	_, ok := r.Caching.Data[ip]
	r.Caching.mu.RUnlock()

	if !ok {
		t.Errorf("expected IP to be cached after lookup")
	}

	// Call again to hit cache
	cachedNames := r.ReverseLookup(ip)
	if len(cachedNames) == 0 {
		t.Errorf("expected cached result, got none")
	}
}

// Test cache limit exceeded behavior
func TestCacheLimitExceeded(t *testing.T) {
	r := NewResolver("", true, 1, 10) // limit 1 entry
	defer r.StopCacheCleaner()

	// Fill cache
	r.Caching.mu.Lock()
	r.Caching.Data[IPToTest] = []string{"jump3.prod.virt."}
	r.Caching.mu.Unlock()

	// Attempt to add new item
	_ = r.ReverseLookup("10.199.226.90")

	r.Caching.mu.RLock()
	if len(r.Caching.Data) > 1 {
		t.Errorf("expected cache limit enforced, but got %d entries", len(r.Caching.Data))
	}
	r.Caching.mu.RUnlock()
}

// Test cache cleaner removes entries after CacheDuration
func TestCacheCleaner(t *testing.T) {
	r := NewResolver("", true, 5, 1) // 1 second cache duration
	defer r.StopCacheCleaner()

	r.Caching.mu.Lock()
	r.Caching.Data[IPToTest] = []string{"jump3.prod.virt."}
	r.Caching.mu.Unlock()

	time.Sleep(1500 * time.Millisecond) // wait for cleaner ticker

	r.Caching.mu.RLock()
	defer r.Caching.mu.RUnlock()
	if len(r.Caching.Data) != 0 {
		t.Errorf("expected cache to be cleared, found %d entries", len(r.Caching.Data))
	}
}

// Test stopping cleaner stops background goroutine gracefully
func TestStopCacheCleaner(t *testing.T) {
	r := NewResolver("", true, 5, 1)
	r.StopCacheCleaner()
	// Call again (should not panic or block)
	r.StopCacheCleaner()
}

// Test without caching enabled
func TestNoCaching(t *testing.T) {
	r := NewResolver("", false, 5, 1)
	defer r.StopCacheCleaner()

	ip := IPToTest
	_ = r.ReverseLookup(ip)

	r.Caching.mu.RLock()
	defer r.Caching.mu.RUnlock()
	if len(r.Caching.Data) != 0 {
		t.Errorf("expected no cache entries when caching disabled")
	}
}
