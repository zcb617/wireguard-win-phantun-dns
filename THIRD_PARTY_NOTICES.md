# Third Party Notices

This distribution contains software licensed from third parties.

## WireGuard Windows

- License: MIT
- Copyright: (C) 2018-2026 WireGuard LLC. All Rights Reserved.
- Source: https://git.zx2c4.com/wireguard-windows/

This is a fork of the official WireGuard for Windows client. The original
WireGuard code is used under the MIT License.

## Phantun

- License: Apache-2.0 (MIT OR Apache-2.0 dual-licensed; this distribution uses
  Apache-2.0)
- Copyright: 2021-2024 Datong Sun (dndx@idndx.com)
- Source: https://github.com/dndx/phantun
- Modifications: WinDivert-based packet interception for Windows (replacing
  Linux TUN); real IP auto-detection; random-port worker binding.

The phantun-client-win code in this repository is a derivative work of Phantun,
used under the Apache License, Version 2.0.

## WinDivert

- License: LGPLv3 / GPLv3 (dual-licensed)
- Copyright: basil00
- Source: https://github.com/basil00/WinDivert
- Used as: dynamic-link library (`WinDivert.dll`) and kernel driver
  (`WinDivert64.sys`)

WinDivert is used via dynamic linking (DLL). In accordance with the LGPL,
the WinDivert source code is available at the URL above. The compiled
binaries (`WinDivert.dll`, `WinDivert64.sys`) are redistributed under the
terms of the LGPLv3/GPLv3 license.
