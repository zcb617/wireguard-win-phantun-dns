# WireGuard for Windows (Enhanced)

[中文](README_CN.md) | English

A fork of the official [WireGuard for Windows](https://github.com/WireGuard/wireguard-windows) client, enhanced with Phantun TCP obfuscation, DNSCrypt proxy, and intelligent DNS-based traffic routing.

## Core Features

### 1. Phantun TCP Obfuscation

Masks WireGuard UDP traffic as TCP connections to bypass firewalls and QoS throttling targeting UDP.

**Setup:**

1. Select a tunnel in the UI, open the **Obfuscation** tab
2. Check **Enable Phantun obfuscation**
3. Fill in **Remote server** (Phantun server address, format `IP:PORT`)
4. **Local listen** is auto-filled with the WG client IP and port (default `127.0.0.1:8080`)
5. Save the configuration; `phantun-client.exe` auto-starts when the tunnel is activated

**AllowedIPs best practice:**

Do not use `0.0.0.0/0` in Peer AllowedIPs when Phantun is enabled, because WireGuard's WFP classify callback will intercept Phantun's fake TCP packets and create a traffic loop.

Correct configuration:

```ini
[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
```

### 2. DNS Encryption (DNSCrypt Proxy)

Runs dnscrypt-proxy inside the tunnel to encrypt DNS queries and prevent DNS hijacking and poisoning.

**Setup:**

1. Select a tunnel in the UI, open the **DNS Proxy** tab
2. Check **Enable DNSCrypt proxy**
3. **Listen address** is auto-filled with the WG client IP and port (default `WG_IP:10053`)
4. Enter **Server names** (e.g., `cloudflare`)
5. Advanced users can paste custom config or sdns:// stamp in **Custom TOML**
6. Save the configuration; `dnscrypt-proxy.exe` auto-starts after WG handshake completes

### 3. IP Traffic Routing (DNS Router)

Intelligent domain-based traffic splitting: matched domains go through the WG tunnel, others use the local network directly. Two modes are supported:

- **AllowedIPs mode**: dynamically adds resolved IPs of matched domains to WG AllowedIPs
- **RouteTable mode** (default): adds resolved IPs as /32 host routes in the system routing table; unmatched traffic goes through the physical adapter

**Setup:**

1. Select a tunnel in the UI, open the **DNS Router** tab
2. Check **Enable DNS router**
3. **Listen address** is auto-filled with the WG client IP and port (default `WG_IP:53`)
4. **Mode**: choose `routetable` (system route table mode) or `allowedips`
5. **Domain list URL**: use the default; the domain rule list is auto-downloaded on first start
6. Save the configuration

When enabled, the physical adapter DNS is temporarily redirected to the DNS Router. All DNS queries are matched against local rules first; matched domains are resolved via dnscrypt-proxy, unmatched domains use the original system DNS.

## Building and Installation

Requires Windows 10 64-bit or later, and Git for Windows.

```text
git clone https://github.com/zcb617/wireguard-win-phantun-dns.git
cd wireguard-win-phantun-dns
build
```

`build.bat` automatically downloads and configures Go, LLVM-MinGW, WireGuardNT, and other dependencies.

To build the installer:

```text
cd installer
build
```

## License

MIT License. See [COPYING](COPYING).
