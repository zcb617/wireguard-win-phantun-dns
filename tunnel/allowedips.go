/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
)

// allowedIPsSyncer maintains a set of IPs that should route through the WG
// tunnel. It receives new IPs from the DNS router and periodically rebuilds
// the AllowedIPs list for the WireGuard adapter.
type allowedIPsSyncer struct {
	adapter      *driver.Adapter
	baseConfig   *conf.Config // original config; never modified directly
	dynamicIPs   map[netip.Addr]time.Time
	mu           sync.RWMutex
	ticker       *time.Ticker
	stop         chan struct{}
	wg           sync.WaitGroup
	ttl          time.Duration
}

func newAllowedIPsSyncer(adapter *driver.Adapter, baseConfig *conf.Config, ttlMinutes int) *allowedIPsSyncer {
	if ttlMinutes <= 0 {
		ttlMinutes = 10
	}
	return &allowedIPsSyncer{
		adapter:    adapter,
		baseConfig: baseConfig,
		dynamicIPs: make(map[netip.Addr]time.Time),
		stop:       make(chan struct{}),
		ttl:        time.Duration(ttlMinutes) * time.Minute,
	}
}

func (s *allowedIPsSyncer) Start() {
	s.ticker = time.NewTicker(30 * time.Second)
	s.wg.Add(1)
	go s.loop()
}

func (s *allowedIPsSyncer) Stop() {
	close(s.stop)
	s.ticker.Stop()
	s.wg.Wait()
}

func (s *allowedIPsSyncer) AddIP(ip netip.Addr) {
	s.mu.Lock()
	s.dynamicIPs[ip] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	// Trigger immediate rebuild so the user doesn't wait 30s.
	s.rebuild()
}

func (s *allowedIPsSyncer) loop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ticker.C:
			s.rebuild()
		case <-s.stop:
			return
		}
	}
}

func (s *allowedIPsSyncer) rebuild() {
	s.mu.Lock()
	now := time.Now()
	for ip, expiry := range s.dynamicIPs {
		if now.After(expiry) {
			delete(s.dynamicIPs, ip)
		}
	}
	// Copy dynamic IPs for building config.
	var dyn []netip.Addr
	for ip := range s.dynamicIPs {
		dyn = append(dyn, ip)
	}
	s.mu.Unlock()

	if len(dyn) == 0 {
		return
	}

	// Build a fresh Config by shallow-copying baseConfig and deep-copying peers.
	cfg := *s.baseConfig
	cfg.Peers = make([]conf.Peer, len(s.baseConfig.Peers))
	copy(cfg.Peers, s.baseConfig.Peers)

	// Convert dynamic IPs to prefixes and append to the first peer.
	var extra []netip.Prefix
	for _, ip := range dyn {
		if ip.Is4() {
			extra = append(extra, netip.PrefixFrom(ip, 32))
		} else {
			extra = append(extra, netip.PrefixFrom(ip, 128))
		}
	}
	if len(cfg.Peers) > 0 {
		cfg.Peers[0].AllowedIPs = slices.Concat(cfg.Peers[0].AllowedIPs, extra)
	}

	driverCfg, size := cfg.ToDriverConfiguration()
	if err := s.adapter.SetConfiguration(driverCfg, size); err != nil {
		log.Printf("AllowedIPs syncer: failed to update adapter: %v", err)
	} else {
		log.Printf("AllowedIPs syncer: updated with %d dynamic IPs", len(dyn))
	}
}
