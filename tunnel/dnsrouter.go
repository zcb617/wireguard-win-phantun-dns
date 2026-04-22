/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// dnsRouter runs a local UDP DNS proxy. It matches queries against a domain
// rule set; matched domains are forwarded to the dnscrypt-proxy upstream,
// others go to the system DNS. Resolved IPs for matched domains are sent
// through wgIPs for AllowedIPs inclusion.
type dnsRouter struct {
	rules         map[string]struct{}
	dnscryptAddr  string
	systemAddr    string
	listenAddr    string
	wgIPs         chan<- net.IP
	server        *dns.Server
	wg            sync.WaitGroup
	domainListURL string
	listPath      string
	stopTicker    chan struct{}
}

func newDNSRouter(rules map[string]struct{}, dnscryptAddr, systemAddr, listenAddr string, wgIPs chan<- net.IP) *dnsRouter {
	return &dnsRouter{
		rules:        rules,
		dnscryptAddr: dnscryptAddr,
		systemAddr:   systemAddr,
		listenAddr:   listenAddr,
		wgIPs:        wgIPs,
	}
}

func (r *dnsRouter) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("DNS router: invalid listen address %s: %w", r.listenAddr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("DNS router: failed to bind %s: %w", r.listenAddr, err)
	}
	r.server = &dns.Server{
		PacketConn: conn,
		Handler:    dns.HandlerFunc(r.handleRequest),
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if err := r.server.ActivateAndServe(); err != nil {
			log.Printf("DNS router stopped: %v", err)
		}
	}()
	// Start background updater if a remote URL is configured.
	if r.domainListURL != "" {
		r.stopTicker = make(chan struct{})
		r.wg.Add(1)
		go r.updateLoop()
	}
	return nil
}

func (r *dnsRouter) Stop() {
	if r.stopTicker != nil {
		close(r.stopTicker)
	}
	if r.server != nil {
		r.server.Shutdown()
	}
	r.wg.Wait()
}

// updateLoop periodically downloads the domain list and reloads rules.
func (r *dnsRouter) updateLoop() {
	defer r.wg.Done()
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.downloadAndReload()
		case <-r.stopTicker:
			return
		}
	}
}

// downloadAndReload fetches the domain list from domainListURL and overwrites
// the local file, then reloads the rules into memory.
func (r *dnsRouter) downloadAndReload() {
	if r.domainListURL == "" {
		return
	}
	resp, err := http.Get(r.domainListURL)
	if err != nil {
		log.Printf("DNS router: failed to download domain list: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("DNS router: domain list download returned status %d", resp.StatusCode)
		return
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("DNS router: failed to read domain list response: %v", err)
		return
	}
	if err := os.WriteFile(r.listPath, data, 0o600); err != nil {
		log.Printf("DNS router: failed to write domain list: %v", err)
		return
	}
	newRules, err := conf.LoadDomainRules(r.listPath)
	if err != nil {
		log.Printf("DNS router: failed to reload domain list: %v", err)
		return
	}
	r.rules = newRules
	log.Printf("DNS router: domain list updated (%d rules)", len(r.rules))
}

func (r *dnsRouter) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")

	matched := conf.MatchDomain(domain, r.rules)
	upstream := r.systemAddr
	if matched {
		upstream = r.dnscryptAddr
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	rsp, _, err := c.Exchange(req, upstream)
	if err != nil {
		log.Printf("DNS router exchange error for %s via %s: %v", domain, upstream, err)
		m := new(dns.Msg)
		m.SetReply(req)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	// If matched and resolved via dnscrypt, notify AllowedIPs syncer.
	if matched && r.wgIPs != nil {
		for _, rr := range rsp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				select {
				case r.wgIPs <- a.A:
				default:
				}
			case *dns.AAAA:
				// TODO: IPv6 support
			}
		}
	}

	w.WriteMsg(rsp)
}

// startDNSRouter creates and starts the DNS router for the given tunnel.
// It queries the system's active physical network adapters for their DNS
// servers to use as the upstream for non-matched domains.
// originalSystemAddrs contains the original DNS servers captured before
// physical adapters were overridden (to avoid loopback query loops).
func startDNSRouter(tunnelName string, dnscryptAddr string, originalSystemAddrs []netip.Addr, wgIPs chan<- net.IP) (*dnsRouter, error) {
	routerCfg, err := conf.LoadDNSRouterConfig(tunnelName)
	if err != nil {
		return nil, err
	}
	if !routerCfg.Enabled {
		return nil, nil
	}

	listPath, err := conf.DomainListPath()
	if err != nil {
		return nil, err
	}
	rules, err := conf.LoadDomainRules(listPath)
	if err != nil {
		log.Printf("DNS router: failed to load domain list from %s: %v", listPath, err)
		rules = make(map[string]struct{})
	}

	listenAddr := routerCfg.ListenAddress
	if listenAddr == "" {
		listenAddr = "127.0.0.1:53"
	}

	// Determine the upstream DNS for non-matched domains.
	// Prefer the original physical adapter DNS captured before override,
	// to avoid querying 127.0.0.1 (which would loop back to ourselves).
	systemAddr := "223.5.5.5:53"
	if len(originalSystemAddrs) > 0 {
		systemAddr = originalSystemAddrs[0].String() + ":53"
	} else {
		// Fallback: query current system DNS (may return loopback if adapters
		// have already been overridden, so avoid this path when possible).
		systemDNSAddrs, err := winipcfg.GetSystemDNSServers()
		if err != nil {
			log.Printf("DNS router: failed to get system DNS servers: %v", err)
		}
		if len(systemDNSAddrs) > 0 {
			systemAddr = systemDNSAddrs[0].String() + ":53"
		}
	}

	router := newDNSRouter(rules, dnscryptAddr, systemAddr, listenAddr, wgIPs)
	router.domainListURL = routerCfg.DomainListURL
	router.listPath = listPath
	if err := router.Start(); err != nil {
		return nil, fmt.Errorf("failed to start DNS router: %w", err)
	}
	log.Printf("DNS router started on %s (%d rules, system DNS: %s)", listenAddr, len(rules), systemAddr)
	return router, nil
}
