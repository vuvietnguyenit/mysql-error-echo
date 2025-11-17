package main

import (
	"context"
	"net"
	"sync"
	"time"
)

type Caching struct {
	Enabled       bool
	CacheSize     int
	CacheDuration time.Duration // use Duration for easier time handling
	Data          map[string][]string
	mu            sync.RWMutex
}

type Resolver struct {
	Caching    *Caching
	Nameserver string
	Resolver   *net.Resolver
	cancelFunc context.CancelFunc
}

func NewResolver(nameserver string, cachingEnabled bool, cacheSize int, cacheDurationSeconds int) *Resolver {
	r := &Resolver{
		Caching: &Caching{
			Enabled:       cachingEnabled,
			CacheSize:     cacheSize,
			CacheDuration: time.Duration(cacheDurationSeconds) * time.Second,
			Data:          make(map[string][]string),
		},
		Nameserver: nameserver,
	}

	if nameserver != "" {
		dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, nameserver)
		}
		r.Resolver = &net.Resolver{
			PreferGo: true,
			Dial:     dialer,
		}
	} else {
		r.Resolver = net.DefaultResolver
	}

	// Start cache cleaner
	ctx, cancel := context.WithCancel(context.Background())
	r.cancelFunc = cancel
	go r.startCacheCleaner(ctx)

	return r
}

// ReverseLookup resolves IP to domain and caches it if successful
func (r *Resolver) ReverseLookup(ip string) []string {
	// Check cache first
	if r.Caching.Enabled {
		r.Caching.mu.RLock()
		if domains, ok := r.Caching.Data[ip]; ok {
			r.Caching.mu.RUnlock()
			slogger.Debug("cache hit for IP", "ip", ip, "domains", domains)
			return domains // get in cache
		}
		r.Caching.mu.RUnlock()
	}

	ptrs, err := r.Resolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return []string{ip}
	}
	// Update cache
	if r.Caching.Enabled {
		r.Caching.mu.Lock()
		defer r.Caching.mu.Unlock()

		if len(r.Caching.Data) >= r.Caching.CacheSize {
			slogger.Warn("cache size limit reached, skipping cache update", "size", r.Caching.CacheSize)
			return ptrs
		}
		r.Caching.Data[ip] = ptrs
	}

	return ptrs
}

// startCacheCleaner runs a ticker to clear cache periodically
func (r *Resolver) startCacheCleaner(ctx context.Context) {
	if !r.Caching.Enabled || r.Caching.CacheDuration <= 0 {
		return
	}

	ticker := time.NewTicker(r.Caching.CacheDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.Caching.mu.Lock()
			slogger.Debug("clearing cache", "entries", len(r.Caching.Data))
			r.Caching.Data = make(map[string][]string) // Reset cache
			r.Caching.mu.Unlock()
		case <-ctx.Done():
			slogger.Debug("cache cleaner stopped")
			return
		}
	}
}

// StopCacheCleaner stops the background cache cleaner
func (r *Resolver) StopCacheCleaner() {
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
}
