/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"log"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetSystemDNSServers returns the DNS server addresses configured on the
// system's active physical network adapters (excluding loopback, tunnels,
// and virtual adapters). These are the addresses that would be used for
// regular DNS resolution before any VPN tunnel is established.
func GetSystemDNSServers() ([]netip.Addr, error) {
	adapters, err := GetAdaptersAddresses(windows.AF_UNSPEC, GAAFlagDefault)
	if err != nil {
		return nil, err
	}

	var servers []netip.Addr
	seen := make(map[netip.Addr]struct{})

	for _, adapter := range adapters {
		// Skip non-operational or virtual adapters.
		if adapter.OperStatus != IfOperStatusUp {
			continue
		}
		if adapter.IfType == IfTypeSoftwareLoopback {
			continue
		}
		if adapter.IfType == IfTypeTunnel {
			continue
		}

		for dns := adapter.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			addr := socketAddressToAddr(dns.Address)
			if !addr.IsValid() {
				continue
			}
			if _, ok := seen[addr]; !ok {
				seen[addr] = struct{}{}
				servers = append(servers, addr)
			}
		}
	}

	return servers, nil
}

// socketAddressToAddr converts a windows.SocketAddress to a netip.Addr.
func socketAddressToAddr(sa windows.SocketAddress) netip.Addr {
	if sa.Sockaddr == nil {
		return netip.Addr{}
	}
	raw := (*RawSockaddrInet)(unsafe.Pointer(sa.Sockaddr))
	return raw.Addr()
}

// RawSockaddrInet is already defined in types.go; the cast above reuses it.
// Ensure the unsafe cast is safe by checking the layout matches syscall.RawSockaddr.
var _ = unsafe.Sizeof(RawSockaddrInet{}) == unsafe.Sizeof(syscall.RawSockaddr{})

// PhysicalDNSOverride holds the original DNS configuration of a physical
// adapter so it can be restored later.
type PhysicalDNSOverride struct {
	luid     LUID
	original []netip.Addr
}

// OverridePhysicalDNS temporarily sets the DNS of all active physical adapters
// to the provided addresses (typically 127.0.0.1) so that system DNS queries
// are forced through a local DNS proxy.
// It returns:
//   - overrides: per-adapter records for restoring DNS later (luid -> original DNS mapping)
//   - originalServers: deduplicated list of all original DNS servers found on physical adapters
func OverridePhysicalDNS(servers []netip.Addr) (overrides []PhysicalDNSOverride, originalServers []netip.Addr, err error) {
	adapters, err := GetAdaptersAddresses(windows.AF_UNSPEC, GAAFlagDefault)
	if err != nil {
		return nil, nil, err
	}

	seen := make(map[netip.Addr]struct{})
	for _, adapter := range adapters {
		if adapter.OperStatus != IfOperStatusUp {
			continue
		}
		if adapter.IfType == IfTypeSoftwareLoopback {
			continue
		}
		if adapter.IfType == IfTypeTunnel {
			continue
		}

		var original []netip.Addr
		for dns := adapter.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			addr := socketAddressToAddr(dns.Address)
			if addr.IsValid() {
				original = append(original, addr)
				if _, ok := seen[addr]; !ok {
					seen[addr] = struct{}{}
					originalServers = append(originalServers, addr)
				}
			}
		}
		if len(original) == 0 {
			continue
		}

		luid := adapter.LUID
		if setErr := luid.SetDNS(windows.AF_INET, servers, nil); setErr != nil {
			log.Printf("OverridePhysicalDNS: failed to set DNS for %s: %v", adapter.FriendlyName(), setErr)
			continue
		}
		overrides = append(overrides, PhysicalDNSOverride{luid: luid, original: original})
	}
	return overrides, originalServers, nil
}

// RestorePhysicalDNS reverts the DNS changes made by OverridePhysicalDNS.
func RestorePhysicalDNS(overrides []PhysicalDNSOverride) {
	for _, o := range overrides {
		if err := o.luid.SetDNS(windows.AF_INET, o.original, nil); err != nil {
			log.Printf("RestorePhysicalDNS: failed to restore DNS: %v", err)
		}
	}
}
