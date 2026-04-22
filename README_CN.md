# WireGuard for Windows（增强版）

基于 [WireGuard for Windows 官方客户端](https://github.com/WireGuard/wireguard-windows) 的二次开发，集成 Phantun TCP 伪装、DNSCrypt 加密代理和智能 DNS 路由分流功能。

## 核心功能

### 1. Phantun TCP 伪装

将 WireGuard 的 UDP 流量伪装为 TCP 连接，帮助绕过针对 UDP 的防火墙限速和 QoS 策略。

**使用方法：**

1. 在 UI 中选中隧道，打开 **Obfuscation** 标签页
2. 勾选 **Enable Phantun obfuscation**
3. 填写 **Remote server**（Phantun 服务端地址，格式 `服务器IP:端口`）
4. **Local listen** 自动填入 WG 客户端 IP 和端口（默认 `127.0.0.1:8080`）
5. 保存配置，激活隧道后自动启动 `phantun-client.exe`

**AllowedIPs 配置建议：**

使用 Phantun 时，Peer 的 AllowedIPs 请勿使用 `0.0.0.0/0`，否则 WireGuard 的 WFP classify callback 会拦截 Phantun 发出的伪造 TCP 包，导致流量循环。

正确写法：

```ini
[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
```

### 2. DNS 加密（DNSCrypt Proxy）

隧道内运行 dnscrypt-proxy，为 DNS 查询提供加密保护，防止 DNS 劫持和污染。

**使用方法：**

1. 在 UI 中选中隧道，打开 **DNS Proxy** 标签页
2. 勾选 **Enable DNSCrypt proxy**
3. **Listen address** 自动填入 WG 客户端 IP 和端口（默认 `WG_IP:10053`）
4. 在 **Server names** 中填写要使用的 dnscrypt 服务器名称（如 `cloudflare`）
5. 高级用户可在 **Custom TOML** 中粘贴自定义配置或 sdns:// stamp
6. 保存配置，隧道 handshake 完成后自动启动 `dnscrypt-proxy.exe`

### 3. IP 路由分流（DNS Router）

根据域名规则智能分流：匹配规则的域名走 WG 隧道，其他域名走本地网络直连。支持两种模式：

- **AllowedIPs 模式**：将匹配域名解析到的 IP 动态加入 WG AllowedIPs
- **RouteTable 模式**（默认）：将匹配域名解析到的 IP 加入系统路由表作为 /32 主机路由，非匹配流量直接走物理网卡

**使用方法：**

1. 在 UI 中选中隧道，打开 **DNS Router** 标签页
2. 勾选 **Enable DNS router**
3. **Listen address** 自动填入 WG 客户端 IP 和端口（默认 `WG_IP:53`）
4. **Mode** 选择 `routetable`（系统路由表模式）或 `allowedips`
5. **Domain list URL** 使用默认即可，首次启动会自动下载域名规则列表
6. 保存配置

启用后，系统物理网卡的 DNS 会被临时重定向到 DNS Router，所有 DNS 查询先经过本地规则匹配，匹配域名通过 dnscrypt-proxy 加密解析，非匹配域名使用原始系统 DNS。

## 构建与安装

需要 Windows 10 64-bit 或更高版本，以及 Git for Windows。

```text
git clone https://github.com/zcb617/wireguard-win-phantun-dns.git
cd wireguard-win-phantun-dns
build
```

`build.bat` 会自动下载并配置 Go、LLVM-MinGW、WireGuardNT 等依赖。

构建安装包：

```text
cd installer
build
```

## 许可证

MIT 许可证。详见 [COPYING](COPYING)。
