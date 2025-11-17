// flags.go
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds parsed CLI options.
type Config struct {
	UseDNS        bool
	CacheSize     int
	CacheDuration time.Duration
	Nameserver    string
	Iface         string
	Port          int
}

func NewFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// DNS-related flags
	fs.Bool("use-dns", false, "Resolve IP to domain (enable DNS reverse lookup)")
	fs.Int("cache-size", 4096, "Maximum number of entries to store in DNS cache")
	fs.Duration("cache-duration", 5*time.Minute, "Duration to keep DNS cache entries (example: 30s, 5m, 1h)")
	fs.String("nameserver", "", "Custom DNS nameserver to use (example: 8.8.8.8:53). Leave empty to use system resolver")

	// Packet processing flags
	fs.String("iface", "eth0", "Network interface to capture/process packets on")
	fs.Int("port", 3306, "MySQL server port to trace")

	return fs
}

func ParseFlags() (*Config, error) {
	fs := NewFlagSet()

	useDNS := fs.Lookup("use-dns").Value
	cacheSize := fs.Lookup("cache-size").Value
	cacheDuration := fs.Lookup("cache-duration").Value
	nameserver := fs.Lookup("nameserver").Value
	iface := fs.Lookup("iface").Value
	port := fs.Lookup("port").Value

	// Parse command line
	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, err
	}

	ud, ok := useDNS.(flag.Getter)
	if !ok {
		return nil, fmt.Errorf("internal error: cannot get use-dns value")
	}
	cs, ok := cacheSize.(flag.Getter)
	if !ok {
		return nil, fmt.Errorf("internal error: cannot get cache-size value")
	}
	cd, ok := cacheDuration.(flag.Getter)
	if !ok {
		return nil, fmt.Errorf("internal error: cannot get cache-duration value")
	}
	ns, ok := nameserver.(flag.Getter)
	if !ok {
		return nil, fmt.Errorf("internal error: cannot get nameserver value")
	}
	ifv, ok := iface.(flag.Getter)
	if !ok {
		return nil, fmt.Errorf("internal error: cannot get iface value")
	}
	pt, ok := port.(flag.Getter)
	if !ok {
		return nil, fmt.Errorf("internal error: cannot get port value")
	}

	cfg := &Config{
		UseDNS:        ud.Get().(bool),
		CacheSize:     cs.Get().(int),
		CacheDuration: cd.Get().(time.Duration),
		Nameserver:    ns.Get().(string),
		Iface:         ifv.Get().(string),
		Port:          pt.Get().(int),
	}

	// Validation
	if cfg.CacheSize <= 0 {
		return nil, fmt.Errorf("cache-size must be > 0")
	}
	if cfg.CacheDuration < 0 {
		return nil, fmt.Errorf("cache-duration must be non-negative")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.Iface == "" {
		return nil, fmt.Errorf("iface must not be empty")
	}

	return cfg, nil
}
