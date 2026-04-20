/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/windows/conf"
)

// dnsRouter runs a local UDP DNS proxy. It matches queries against a domain
// rule set; matched domains are forwarded to the dnscrypt-proxy upstream,
// others go to the system DNS. Resolved IPs for matched domains are sent
// through wgIPs for AllowedIPs inclusion.
type dnsRouter struct {
	rules       map[string]struct{}
	dnscryptAddr string
	systemAddr   string
	listenAddr   string
	wgIPs        chan<- net.IP
	server       *dns.Server
	wg           sync.WaitGroup
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
	r.server = &dns.Server{
		Addr:    r.listenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(r.handleRequest),
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if err := r.server.ListenAndServe(); err != nil {
			log.Printf("DNS router stopped: %v", err)
		}
	}()
	return nil
}

func (r *dnsRouter) Stop() {
	if r.server != nil {
		r.server.Shutdown()
	}
	r.wg.Wait()
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
// systemDNSAddrs contains the original DNS servers from the WireGuard config
// (before they were overridden by local proxies), used for non-matched domains.
func startDNSRouter(tunnelName string, dnscryptAddr string, systemDNSAddrs []string, wgIPs chan<- net.IP) (*dnsRouter, error) {
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

	// Use the first original DNS as the system upstream.
	systemAddr := "223.5.5.5:53"
	if len(systemDNSAddrs) > 0 {
		systemAddr = systemDNSAddrs[0]
	}

	router := newDNSRouter(rules, dnscryptAddr, systemAddr, listenAddr, wgIPs)
	if err := router.Start(); err != nil {
		return nil, fmt.Errorf("failed to start DNS router: %w", err)
	}
	log.Printf("DNS router started on %s (%d rules, system DNS: %s)", listenAddr, len(rules), systemAddr)
	return router, nil
}
