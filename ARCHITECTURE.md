# WireGuard for Windows（增强版）技术架构详解

## 一、项目背景与动机

WireGuard 以其简洁、高效的设计成为现代 VPN 的首选协议，但在某些网络环境中仍面临挑战：

1. **UDP 被限速或阻断**：运营商和企业防火墙常对 UDP 流量实施 QoS 限速，甚至直接丢弃 UDP 包，导致 WireGuard 连接不稳定或速度受限。
2. **DNS 劫持与污染**：未加密的 DNS 查询容易被中间人篡改，导致域名解析结果被污染，无法访问目标服务。
3. **全隧道 vs 分流**：传统 `AllowedIPs = 0.0.0.0/0` 会将所有流量导入 VPN 隧道，造成不必要的延迟和带宽消耗；而手动维护分流规则既繁琐又容易过时。

本项目基于 [WireGuard for Windows 官方客户端](https://github.com/WireGuard/wireguard-windows) 进行二次开发，在不改动 WireGuard 核心协议的前提下，通过三个独立组件的有机协作，解决了上述问题。

---

## 二、整体架构

### 2.1 进程模型

官方 WireGuard for Windows 采用三层架构：

```
UI 进程（用户态）
    ↓ gob IPC（命名管道）
Manager 服务（SYSTEM 权限）
    ↓ Windows SCM
Tunnel 服务（每隧道一个，SYSTEM 权限）
    ↓ WireGuardNT 驱动
虚拟网卡适配器
```

本项目的增强完全集中在 **Tunnel 服务** 层。当 Tunnel 服务启动时，除了创建 WireGuard 虚拟网卡、加载配置、执行 PreUp/PostUp 脚本外，还会根据隧道的附加配置文件按需启动三个子进程：

- **phantun-client.exe**：UDP-to-TCP 流量伪装
- **dnscrypt-proxy.exe**：DNS 加密代理
- **dns-router（内嵌）**：基于域名规则的智能分流

三个组件之间通过 Go channel 和文件系统传递状态，与 UI 的通信则通过 Manager 中转。

### 2.2 配置文件体系

每个隧道除了标准的 `.conf` 配置文件外，还引入了三份独立的 JSON 配置：

| 文件后缀 | 组件 | 说明 |
|---------|------|------|
| `.phantun.json` | Phantun | 启用状态、远程服务器地址、本地监听端口 |
| `.dnscrypt.json` | DNSCrypt | 启用状态、监听地址、服务器名称、自定义 TOML |
| `.dnsrouter.json` | DNS Router | 启用状态、监听地址、域名列表 URL、分流模式、TTL |

这些配置文件存放在 `C:\Program Files\WireGuard\Data\Configurations\` 目录下，与主配置同名，仅后缀不同。UI 通过 IPC 调用 Manager 的 `SavePhantunConfig`/`LoadPhantunConfig` 等方法读写这些文件。

### 2.3 状态通信机制

Tunnel 服务与 Manager 服务之间没有直接的 IPC 通道，唯一的通信方式是 **Windows 服务控制管理器（SCM）** 的状态查询。为了将子进程（phantun、dnscrypt-proxy、dns-router）的运行状态实时反馈到 UI，本项目引入了 **文件中转** 机制：

1. **Tunnel → 文件**：Tunnel 服务在启动某个子进程后，将对应的布尔标志（`phantun_running`、`dnscrypt_running`、`dnsrouter_running`）写入 JSON 文件 `{tunnel-name}.status.json`。
2. **文件 → Manager**：Manager 服务收到 UI 的 `ProcessStatus` IPC 请求时，读取上述 JSON 文件并返回。
3. **Manager → UI**：UI 的 `ConfView` 每秒通过 ticker 轮询一次进程状态，并在界面的 **Components** 分组中显示 Running / Not running。

Tunnel 服务停止时，defer 函数会清空状态并删除 `.status.json` 文件，确保 UI 正确显示 Not running。

---

## 三、Phantun TCP 伪装

### 3.1 原理

Phantun 是一个 UDP-to-TCP 伪装工具。它在客户端和服务端之间建立 TCP 连接，然后将 WireGuard 的 UDP 数据包封装在 TCP 流中传输。对中间网络设备而言，流量看起来像普通的 TCP 连接（如 HTTPS），从而绕过针对 UDP 的 QoS 策略和防火墙规则。

本项目使用的是 [phantun-client-win](https://github.com/zcb617/phantun-client-win)——Phantun 的 Windows 移植版，基于 WinDivert 在用户态拦截和重写网络包。

### 3.2 集成方式

Phantun 的集成发生在 Tunnel 服务启动的早期阶段，在 WG 虚拟网卡创建之前：

1. **配置加载**：Tunnel 服务读取 `.phantun.json`，检查 `enabled` 和 `remote` 字段。
2. **可执行文件检查**：在同目录下查找 `phantun-client.exe`，若不存在则报错退出。
3. **备份原始 Endpoint**：遍历所有 Peer，将原始 `Endpoint` 保存到 `originalEndpoints` 切片。
4. **重定向 Endpoint**：将所有 Peer 的 `Endpoint` 替换为 `127.0.0.1:{phantun_local_port}`。这样 WireGuard 内核仍然以为自己在向原来的服务器发 UDP 包，但实际上这些包被发到了本地 Phantun 代理。
5. **启动进程**：以 `HideWindow` 模式启动 `phantun-client.exe`，参数为 `--remote`、`--local` 和 `--ipv4-only`。
6. **进程守护**：`phantunProcess` 变量持有进程句柄，Tunnel 服务停止时通过 `Kill()` + `Wait()` 确保进程被清理。

### 3.3 AllowedIPs 陷阱与解决

当 `AllowedIPs = 0.0.0.0/0` 时，WireGuardNT 驱动会启用 NDIS WFP classify callback，拦截所有出站流量。Phantun 通过 WinDivert 注入的伪造 TCP 包恰好也会被这个 callback 捕获，导致：

```
WG 内核 → 加密 UDP 包 → 127.0.0.1:8080
    ↓
Phantun 封装为 TCP → WinDivert 注入
    ↓
WFP callback 拦截 → 重新进入 WG 内核
    ↓
死循环
```

解决方案是将 `0.0.0.0/0` 拆分为 `0.0.0.0/1, 128.0.0.0/1`。这两段前缀合起来覆盖了整个 IPv4 地址空间，但 WireGuardNT 不会将其识别为"全隧道"信号，从而避免启用 aggressive classify callback。WinDivert 注入的 TCP 包就能正常从物理网卡发出。

---

## 四、DNS 加密（DNSCrypt Proxy）

### 4.1 原理

dnscrypt-proxy 是一个支持 DNSCrypt、DoH（DNS over HTTPS）和 ODoH（Oblivious DoH）的 DNS 代理。它将传统的明文 UDP DNS 查询转换为加密的 HTTPS 或 DNSCrypt 查询，防止中间人窃听和篡改。

### 4.2 集成方式

DNSCrypt 的启动被**有意延迟**到 WG 隧道 handshake 完成之后。原因是 dnscrypt-proxy 需要绑定到 WG 接口的 IP 地址（如 `10.8.0.2:10053`），而 WG 接口 IP 只有在驱动配置生效、适配器状态变为 UP 之后才可用。

启动流程如下：

1. **配置加载**：读取 `.dnscrypt.json`。
2. **TOML 生成**：根据配置生成 `dnscrypt-proxy-{tunnel}.toml`：
   - 若用户填写了 **Custom TOML**，则解析并补全 `listen_addresses`。
   - 若只提供了 sdns:// stamp，则自动包裹为 `[static]` 配置块。
   - 否则生成默认配置，包含 `public-resolvers` 源和指定的 `server_names`。
3. **进程启动**：在 `watcher.started` 事件触发后（表示 WG 握手完成、接口已 UP），启动 `dnscrypt-proxy.exe`，标准输出和标准错误重定向到日志文件 `dnscrypt-proxy-{tunnel}.log`。
4. **重试机制**：启动失败时自动重试最多 3 次（间隔 1 秒），应对 WG IP 尚未完全就绪的竞态条件。

### 4.3 与 DNS Router 的协作

DNSCrypt 启动后监听在 WG 接口 IP 上（如 `10.8.0.2:10053`）。DNS Router 将这个地址作为"加密上游"：匹配规则的域名查询会被转发到 dnscrypt-proxy，由它通过加密通道解析。这样，被分流进 WG 隧道的域名不仅走了 VPN，其 DNS 查询也是加密的。

---

## 五、DNS 路由与智能分流

### 5.1 架构

DNS Router 是一个内嵌在 Tunnel 服务中的 UDP DNS 代理，基于 [miekg/dns](https://github.com/miekg/dns) 库实现。它充当系统 DNS 的"前置过滤器"：

```
应用程序 DNS 查询
    ↓
系统 DNS（被临时修改为 DNS Router 地址）
    ↓
DNS Router（127.0.0.1:53 或 WG_IP:53）
    ├─ 域名匹配规则？
    │   ├─ 是 → 转发到 dnscrypt-proxy → 加密解析 → 返回结果
    │   │                                      ↓
    │   │                              将解析到的 IP 发给 syncer
    │   └─ 否 → 转发到原始系统 DNS → 明文解析 → 返回结果
    ↓
应用程序
```

### 5.2 域名规则

规则文件 `wg_domain_list.txt` 采用 dnsmasq 格式（`server=/domain/`），首次使用时从配置的 URL 自动下载。DNS Router 每小时后台检查一次更新。

匹配采用**后缀匹配**：`www.google.com` 可以匹配规则 `google.com`。这意味着只需维护一级域名即可覆盖所有子域名。

### 5.3 物理网卡 DNS 重定向

启用 DNS Router 时，Tunnel 服务会调用 `winipcfg.OverridePhysicalDNS()`，将所有物理网卡的 DNS 服务器临时替换为 DNS Router 的监听地址（如 `127.0.0.1`）。这样：

- 无论应用程序指定哪个网卡发 DNS 查询，都会先经过 DNS Router。
- Tunnel 停止时，`RestorePhysicalDNS()` 自动恢复原始 DNS 设置。
- 原始系统 DNS 地址被保存为 `originalServers`，供 DNS Router 作为"非匹配域名"的上游使用，避免查询环路。

### 5.4 两种分流模式

DNS Router 解析到匹配域名的 IP 后，需要决定如何将这些 IP 的流量导入 WG 隧道。本项目提供两种模式：

#### 5.4.1 AllowedIPs 模式

将解析到的 IP 动态添加到 WireGuard 驱动的 AllowedIPs 列表中。实现上通过 `allowedIPsSyncer` 完成：

- `AddIP(ip)` 将 IP 加入内存中的集合，并调用 `adapter.SetConfiguration()` 更新驱动配置。
- TTL 过期后自动从集合中移除，并重新下发驱动配置。

**优点**：与 WG 原生路由机制一致，无需修改系统路由表。
**缺点**：频繁调用 `SetConfiguration()` 有一定开销；大量 IP 时驱动配置体积增大。

#### 5.4.2 RouteTable 模式（默认）

将解析到的 IP 作为 /32（IPv4）或 /128（IPv6）主机路由添加到系统路由表中，下一跳为 WG 接口，metric 设为 5（低于默认路由的 metric）。实现上通过 `routeTableSyncer` 完成：

- `AddIP(ip)` 调用 `winipcfg.LUID.AddRoute(prefix, nextHop, metric)`。
- TTL 过期后调用 `DeleteRoute()` 清理。
- **关键修复**：从 `AllowedIPs` 初始化的 /32 IP（如 WG 服务器内网 IP）被标记为 `permanentRoutes`，不受 TTL 过期影响，确保隧道基础连通性不会因路由清理而中断。

**优点**：不改动 WG 驱动配置，性能更好；路由表操作是标准的 Windows 网络机制，兼容性好。
**缺点**：需要维护系统路由表的生命周期，停止时必须全部清理。

两种模式的选择在 `.dnsrouter.json` 的 `mode` 字段中配置，UI 提供下拉框切换。

---

## 六、服务生命周期与启动时序

Tunnel 服务的启动和停止是一个精心编排的多阶段过程，确保各组件按正确顺序初始化：

### 6.1 启动时序

```
1. 加载主配置 (.conf)
2. 解析 Endpoint DNS 名称
3. 启动 Phantun 客户端（如配置）
   └─ 重定向 Peer Endpoints 到本地代理
4. 生成 DNSCrypt TOML（如配置）
   └─ 此时不启动 dnscrypt-proxy，WG IP 尚不可用
5. 配置 DNS Router（如配置）
   └─ 保存原始 DNS，准备覆盖物理网卡 DNS
6. 创建 WG 虚拟网卡适配器
7. SetConfiguration() — 下发 WG 配置到驱动
   └─ 若 RouteTable 模式：提前设置 TableOff = true
8. SetAdapterState(UP) — 激活网卡
9. 等待 watcher.started 事件（WG handshake 完成）
10. 启动 dnscrypt-proxy（如配置）
    └─ 绑定 WG IP，最多重试 3 次
11. 启动 DNS Router（如配置）
    └─ 覆盖物理网卡 DNS
12. 启动 syncer（如配置）
    └─ 开始接收 DNS Router 解析到的 IP
```

### 6.2 停止时序（defer 清理）

```
1. 清空进程状态文件
2. 停止 Phantun 进程
3. 停止 dnscrypt-proxy 进程
4. 停止 DNS Router
5. 停止 syncer（清理所有动态路由或 AllowedIPs）
6. 恢复原始 DNS 配置
7. 执行 PreDown 脚本
8. 销毁接口监听器
9. 关闭 WG 适配器
10. 执行 PostDown 脚本
```

### 6.3 关键时序修复

开发过程中遇到并修复了两个关键时序问题：

1. **TableOff 设置时机**：`config.Interface.TableOff = true` 必须在 `adapter.SetConfiguration()` 之前设置，否则驱动看不到该标志，仍会添加默认路由，导致 RouteTable 模式失效。

2. **DNS 服务启动时机**：dnscrypt-proxy 和 DNS Router 必须在 `watcher.started` 之后启动。早期版本在网卡创建后立即启动，此时 WG IP（如 `10.8.0.2`）尚未分配给系统，bind 操作返回 `bind: cannot assign requested address`。

---

## 七、进程状态显示

为了让用户直观掌握三个子组件的运行状态，本项目在 UI 的隧道详情页增加了 **Components** 分组：

- **Phantun obfuscation**：Running / Not running
- **DNSCrypt proxy**：Running / Not running
- **DNS router**：Running / Not running

状态通过前述的 JSON 文件中转机制实现：

1. Tunnel 服务在成功启动某个子进程后，设置 `processStatus.PhantunRunning = true`（或对应字段），调用 `Save()` 写入文件。
2. UI 的 `ConfView` 每秒通过 `tunnel.ProcessStatus()` IPC 调用查询状态。
3. Manager 读取 `.status.json` 并返回；若文件不存在则返回全 false。
4. UI 调用 `applyProcessStatus()` 更新界面文本。

这种设计避免了 UI 直接查询进程句柄（跨进程权限问题），也避免了复杂的 Tunnel→Manager 反向 IPC，简单而可靠。

---

## 八、安装与打包

### 8.1 构建流程

项目使用 `build.bat` 自动化构建：

1. 下载并验证 Go 1.26、LLVM-MinGW、ImageMagick、WireGuard 工具链、WireGuardNT 驱动。
2. 渲染 SVG 图标为 Windows ICO 格式。
3. 调用 `windres` 编译资源文件（版本号、图标等）。
4. `go build` 生成 `wireguard.exe`（x86 / amd64 / arm64）。
5. 编译 `wg.exe` 命令行工具。

### 8.2 安装包

`installer/build.bat` 使用 WiX Toolset 生成 MSI：

- 包含 `phantun-client.exe`、`WinDivert.dll`、`WinDivert64.sys`。
- 包含 `dnscrypt-proxy.exe`。
- 包含默认域名规则文件 `wg_domain_list.txt`（`NeverOverwrite`）。
- 升级策略：`MajorUpgrade Schedule="afterInstallInitialize"`，确保新版本安装前自动卸载旧版本。

---

## 九、与官方客户端的差异总结

| 维度 | 官方 WireGuard for Windows | 本项目 |
|------|---------------------------|--------|
| Phantun 支持 | 无 | 内置，每隧道独立配置 |
| DNS 加密 | 无 | 内置 dnscrypt-proxy |
| 智能分流 | 无 | DNS Router + 域名规则 |
| 分流实现 | 手动 AllowedIPs | 动态 AllowedIPs / 系统路由表 |
| 进程状态显示 | 仅 WG 服务状态 | WG + Phantun + DNSCrypt + DNS Router |
| 配置文件 | 仅 .conf | .conf + .phantun.json + .dnscrypt.json + .dnsrouter.json |

---

## 十、结语

本项目在保持 WireGuard 协议和官方客户端架构不变的前提下，通过"配置分离 + 进程编排 + 状态中转"的设计，将三个独立工具有机整合为一个用户体验流畅的 VPN 客户端。所有增强都发生在 Tunnel 服务层，不涉及 WG 加密协议和驱动改动，因此安全性和兼容性都有保障。

源代码和构建说明参见 [GitHub 仓库](https://github.com/zcb617/wireguard-win-phantun-dns)。
