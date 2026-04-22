/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// routeTableSyncer maintains a set of /32 host routes on the WireGuard
// interface. It receives new IPs from the DNS router and adds routes so
// that traffic to those IPs is forwarded through the WG tunnel.
// Expired routes are periodically removed from the route table.
type routeTableSyncer struct {
	luid            winipcfg.LUID
	dynamicRoutes   map[netip.Addr]time.Time
	permanentRoutes map[netip.Addr]struct{}
	mu              sync.RWMutex
	ticker          *time.Ticker
	stop            chan struct{}
	wg              sync.WaitGroup
	ttl             time.Duration
}

func newRouteTableSyncer(luid winipcfg.LUID, ttlMinutes int) *routeTableSyncer {
	if ttlMinutes <= 0 {
		ttlMinutes = 10
	}
	return &routeTableSyncer{
		luid:            luid,
		dynamicRoutes:   make(map[netip.Addr]time.Time),
		permanentRoutes: make(map[netip.Addr]struct{}),
		stop:            make(chan struct{}),
		ttl:             time.Duration(ttlMinutes) * time.Minute,
	}
}

func (s *routeTableSyncer) Start() {
	s.ticker = time.NewTicker(30 * time.Second)
	s.wg.Add(1)
	go s.loop()
}

func (s *routeTableSyncer) Stop() {
	close(s.stop)
	s.ticker.Stop()
	s.wg.Wait()
	// Clean up all routes we added.
	s.flush()
}

func (s *routeTableSyncer) AddIP(ip netip.Addr) {
	s.mu.Lock()
	_, exists := s.dynamicRoutes[ip]
	s.dynamicRoutes[ip] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	if !exists {
		s.addRoute(ip)
	}
}

func (s *routeTableSyncer) AddPermanent(ip netip.Addr) {
	s.mu.Lock()
	_, exists := s.permanentRoutes[ip]
	s.permanentRoutes[ip] = struct{}{}
	s.mu.Unlock()
	if !exists {
		s.addRoute(ip)
	}
}

func (s *routeTableSyncer) loop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ticker.C:
			s.reap()
		case <-s.stop:
			return
		}
	}
}

func (s *routeTableSyncer) reap() {
	s.mu.Lock()
	now := time.Now()
	var expired []netip.Addr
	for ip, expiry := range s.dynamicRoutes {
		if now.After(expiry) {
			// Skip if this IP also exists in permanent routes
			if _, ok := s.permanentRoutes[ip]; ok {
				continue
			}
			expired = append(expired, ip)
			delete(s.dynamicRoutes, ip)
		}
	}
	s.mu.Unlock()
	for _, ip := range expired {
		s.deleteRoute(ip)
	}
}

func (s *routeTableSyncer) flush() {
	s.mu.Lock()
	var all []netip.Addr
	for ip := range s.dynamicRoutes {
		all = append(all, ip)
	}
	s.dynamicRoutes = make(map[netip.Addr]time.Time)
	for ip := range s.permanentRoutes {
		all = append(all, ip)
	}
	s.permanentRoutes = make(map[netip.Addr]struct{})
	s.mu.Unlock()
	for _, ip := range all {
		s.deleteRoute(ip)
	}
}

func (s *routeTableSyncer) addRoute(ip netip.Addr) {
	var prefix netip.Prefix
	var nextHop netip.Addr
	if ip.Is4() {
		prefix = netip.PrefixFrom(ip, 32)
		nextHop = netip.IPv4Unspecified()
	} else {
		prefix = netip.PrefixFrom(ip, 128)
		nextHop = netip.IPv6Unspecified()
	}
	// Metric 5: lower than typical default route metric, so WG interface wins.
	if err := s.luid.AddRoute(prefix, nextHop, 5); err != nil {
		log.Printf("Route syncer: failed to add route %s: %v", prefix, err)
	} else {
		log.Printf("Route syncer: added route %s via WG interface", prefix)
	}
}

func (s *routeTableSyncer) deleteRoute(ip netip.Addr) {
	var prefix netip.Prefix
	var nextHop netip.Addr
	if ip.Is4() {
		prefix = netip.PrefixFrom(ip, 32)
		nextHop = netip.IPv4Unspecified()
	} else {
		prefix = netip.PrefixFrom(ip, 128)
		nextHop = netip.IPv6Unspecified()
	}
	if err := s.luid.DeleteRoute(prefix, nextHop); err != nil {
		log.Printf("Route syncer: failed to delete route %s: %v", prefix, err)
	} else {
		log.Printf("Route syncer: deleted route %s", prefix)
	}
}
