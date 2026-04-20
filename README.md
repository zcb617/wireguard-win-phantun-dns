# [WireGuard](https://www.wireguard.com/) for Windows with Phantun Obfuscation

This is a fork of the official WireGuard for Windows client, enhanced with [Phantun](https://github.com/dndx/phantun) UDP-to-TCP obfuscation support.

## Features

- All features from the official WireGuard for Windows client
- **Obfuscation tab**: Configure Phantun per-tunnel to mask WireGuard UDP traffic as TCP
- Auto-starts `phantun-client.exe` when a tunnel with obfuscation enabled is activated
- Transparently redirects peer endpoints through the local Phantun proxy

## Phantun Integration

Phantun is a UDP-to-TCP obfuscation tool that makes WireGuard traffic look like regular TCP connections. This helps bypass firewalls and QoS throttling that target UDP.

### How it works

1. In the UI, select a tunnel and open the **"Obfuscation"** tab
2. Enable Phantun, set the **Remote server** (Phantun server address), and optionally adjust the **Local listen** address (default `127.0.0.1:8080`)
3. Save the configuration
4. When the tunnel is activated, the client automatically starts `phantun-client.exe` and redirects all peer endpoints to the local Phantun proxy
5. On tunnel deactivation, the Phantun process is cleanly shut down

### Important: AllowedIPs Configuration (Best Practice)

When using Phantun obfuscation, **do not use `AllowedIPs = 0.0.0.0/0`** in your WireGuard tunnel configuration.

**Why:** WireGuard treats `0.0.0.0/0` as a "full tunnel" signal and enables an aggressive NDIS classify callback that intercepts **all** outbound traffic at the WFP layer. When Phantun's fake TCP packets are injected by WinDivert, they are immediately caught by this classify callback, re-encrypted, and sent back into the tunnel toward `127.0.0.1:8080`, creating an infinite loop.

**Solution:** Use `0.0.0.0/1, 128.0.0.0/1` instead. This covers the entire IPv4 address space identically, but WireGuard handles it as ordinary route entries rather than triggering the full-tunnel classify mode. WinDivert-injected packets will then bypass WireGuard and exit through the physical adapter normally.

```ini
[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
```

If you also need IPv6 coverage:

```ini
[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
```

### Prerequisite: Phantun Client Binaries

Before building or running, you need the Phantun client binaries and the WinDivert driver:

| File | Purpose |
|------|---------|
| `phantun-client.exe` | Phantun client executable |
| `WinDivert.dll` | WinDivert user-mode DLL |
| `WinDivert64.sys` | WinDivert kernel driver (64-bit) |

These files are included in this repository under `phantun-client-win/`. They were built from the [phantun-client-win](https://github.com/zcb617/phantun-client-win) project.

### Related Projects

- **[phantun-client-win](https://github.com/zcb617/phantun-client-win)** — Windows port of Phantun using WinDivert for packet interception. This project is used as the obfuscation backend.

## Download & Install

If you've come here looking to simply run WireGuard for Windows, [the main download page has links](https://www.wireguard.com/install/). There you will find two things:

- [The WireGuard Installer](https://download.wireguard.com/windows-client/wireguard-installer.exe) &ndash; This selects the most recent version for your architecture, downloads it, checks signatures and hashes, and installs it.
- [Standalone MSIs](https://download.wireguard.com/windows-client/) &ndash; These are for system admins who wish to deploy the MSIs directly. For most end users, the ordinary installer takes care of downloading these automatically.

> **Note**: This fork (with Phantun support) does not have official pre-built releases. You must build from source or use the installer build process described below.

## Building from Source (Windows)

Windows 10 64-bit or later, and Git for Windows are required.

### 1. Clone the repository

```text
C:\Projects> git clone git@github.com:zcb617/wireguard-win-phantun-dns.git
C:\Projects> cd wireguard-win-phantun-dns
```

### 2. Build

```text
C:\Projects\wireguard-win-phantun-dns> build
```

The `build.bat` script will automatically download, verify, and extract the required dependencies (Go, LLVM-MinGW, ImageMagick, WireGuard tools, WireGuardNT driver).

### 3. Run

```text
C:\Projects\wireguard-win-phantun-dns> amd64\wireguard.exe
```

Since WireGuard requires a driver to be installed, and this generally requires a valid Microsoft signature, you may benefit from first installing a release of WireGuard for Windows from the official [wireguard.com](https://www.wireguard.com/install/) builds, which bundles a Microsoft-signed driver, and then subsequently run your own `wireguard.exe`. Alternatively, you can craft your own installer using the `quickinstall.bat` script.

### Building the Installer (Optional)

To build the `.msi` installer that includes the Phantun binaries:

1. Ensure `phantun-client.exe`, `WinDivert.dll`, and `WinDivert64.sys` are available (see **Prerequisite: Phantun Client Binaries** above).
2. Build the installer:

```text
C:\Projects\wireguard-win-phantun-dns> cd installer
C:\Projects\wireguard-win-phantun-dns\installer> build
```

## Documentation

In addition to this [`README.md`](README.md), the following documents are also available:

- [`adminregistry.md`](docs/adminregistry.md) &ndash; A list of registry keys settable by the system administrator for changing the behavior of the application.
- [`attacksurface.md`](docs/attacksurface.md) &ndash; A discussion of the various components from a security perspective, so that future auditors of this code have a head start in assessing its security design.
- [`buildrun.md`](docs/buildrun.md) &ndash; Instructions on building, localizing, running, and developing for this repository.
- [`enterprise.md`](docs/enterprise.md) &ndash; A summary of various features and tips for making the application usable in enterprise settings.
- [`netquirk.md`](docs/netquirk.md) &ndash; A description of various networking quirks and "kill-switch" semantics.

## License

This repository is MIT-licensed.

```text
Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
