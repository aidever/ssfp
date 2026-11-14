# ssfp

**出口 TCP 指纹跟随设备系统的 Shadowsocks 2022 服务端。**

普通的 SS 服务端替你连网站时，网站看到的 TCP 连接是服务器 Linux 内核发出的：TTL 64、窗口 64240、`mss,sok,ts,nop,ws` 选项顺序。
而浏览器自报的是 Windows / macOS / Android。被动指纹（p0f 一类）一比对，"TCP 层是 Linux、浏览器说自己是 Windows"就是代理的明显特征。

ssfp 给每台设备一把密钥，按设备的系统模板发出站连接：Windows 设备出去的 SYN 就是 Windows 的样子，Mac 就是 Mac 的样子。

> English summary: ssfp is a Shadowsocks 2022 server whose outbound TCP/IP fingerprint (TTL, window, window scale, option layout, timestamps) matches the client device's OS. Each device gets its own key mapped to an OS template; SYN option layout is rewritten by a small TC eBPF program. Includes a web console, a CLI, Clash subscriptions and per-device traffic stats. Companion test target: https://github.com/aidever/fpprobe

## 实测

出口为同一台 Linux 服务器，目标为 [fpprobe](https://github.com/aidever/fpprobe) 靶机，p0f 识别结果：

| 设备模板 | 网站看到的 SYN | p0f 判定 |
|---|---|---|
| 不改（普通 SS） | TTL 64 · `mss*44,7:mss,sok,ts,nop,ws` | Linux |
| windows | TTL 128 · `65535,8:mss,nop,ws,nop,nop,sok` | Windows 10 |
| apple | TTL 64 · `65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1` | Mac OS X |
| android | TTL 64 · `65535,9:mss,sok,ts,nop,ws` | Android |
| linux | TTL 64 · `mss*44,7:mss,sok,ts,nop,ws` | Linux |

模板值取自真机直连 `fpprobe` 的实测（Windows 10/11 Chrome、macOS Chrome、Android 10 Chrome）。

## 功能

- **按设备的出口指纹**：TTL / hop limit、窗口缩放（`TCP_WINDOW_CLAMP`）、SYN 窗口、选项顺序与时间戳（TC egress eBPF 改写），UDP 出站也按模板设 TTL
- **密钥 → 设备 → 模板**：每台设备一把 SS2022 用户密钥（EIH 多用户），模板可固定，也可设为 `auto` 按设备访问的系统服务域名自动学习
- **管理看板**：用户、设备、模板、在线连接、按天流量；只监听内网地址，经 ssfp 本身访问
- **`ssfp ctl` 命令行**：增删用户和设备、打印链接与 Clash 订阅
- **Clash 订阅**：每台设备一个节点 + 一个包含全部节点的分组，可带 `dialer-proxy`
- **其他出口特征**：首包随连接建立立即发出（没有"握手完空等"的间隔）；默认丢弃 UDP 443（QUIC），让浏览器走 TCP；默认拒绝访问内网地址

## 工作原理

```mermaid
flowchart LR
  B[浏览器] --> C[Clash / SS 客户端]
  C -- "SS2022（设备密钥）" --> S[ssfp]
  S -- "按设备模板拨号<br/>TTL · wscale · SO_MARK" --> K[Linux 内核]
  K -- "SYN" --> E["eBPF (TC egress)<br/>按 mark 改窗口与选项顺序"]
  E --> W[网站]
```

1. 握手时按用户密钥找到设备，取设备模板（固定 > 自动学到的 > 客户端特征 > 默认）。
2. 出站 socket 设 TTL、用 `TCP_WINDOW_CLAMP` 让内核选出目标 wscale，并打上 `SO_MARK`。
3. 挂在出口网卡 egress 的 eBPF 程序只处理带这个 mark 的本机 SYN：按模板改写窗口值和选项布局（MSS、wscale、时间戳的值沿用内核的），用 `bpf_skb_change_tail` 调整长度并增量更新校验和。其余包原样放行。
4. 时间戳关掉的模板（Windows）在 SYN 里去掉 TS 选项，对端 SYN-ACK 也就不带 TS，内核自然按无时间戳处理。

为什么不全靠客户端特征自动识别：客户端走中转（例如 Clash 的 `dialer-proxy`）时，ssfp 看到的是中转服务器的 SYN；Chrome 在各系统上的 TLS 指纹（JA4）也相同。可靠的设备识别只剩密钥本身，所以按设备分密钥。

## 仓库结构

| 目录 | 内容 |
|---|---|
| `server/` | `ssfp` 服务端：SS2022 中继、eBPF 程序（`bpf/`）、看板（`src/console.*`）、`ssfp ctl`、部署样例（`deploy/`） |
| `fpcore/` | SYN 解析与指纹模板，服务端和靶机共用 |
| `tools/ja4_table.py` | 从 `fpprobe` 访问记录生成 JA4 → 系统对照表（可选） |

## 构建

需要 Rust（stable）、clang（编译 eBPF）、Linux 内核头文件。在 Debian / Ubuntu 上：

```sh
apt install clang linux-libc-dev musl-tools
rustup target add x86_64-unknown-linux-musl

cd server
cargo build --release --target x86_64-unknown-linux-musl   # 静态二进制：target/x86_64-unknown-linux-musl/release/ssfp
cargo test --release
```

## 部署

要求：Linux x86_64，root 或 `CAP_NET_ADMIN` + `CAP_BPF`。在 Ubuntu 24.04（内核 6.8）上测试；内核 ≥ 6.6 时 eBPF 以 TCX 方式挂载，进程退出自动卸载。

```sh
install -m 755 ssfp /usr/local/bin/ssfp
install -d -m 700 /etc/ssfp
install -m 600 server/deploy/config.example.toml /etc/ssfp/config.toml   # 按注释修改
install -m 644 server/deploy/ssfp.service /etc/systemd/system/
install -m 644 server/deploy/99-ssfp.conf /etc/sysctl.d/ && sysctl --system
systemctl daemon-reload && systemctl enable --now ssfp
```

配置要点（`/etc/ssfp/config.toml`）：

```toml
listen = "0.0.0.0:8388"
method = "2022-blake3-aes-128-gcm"
password = "服务端 PSK，openssl rand -base64 16"
public_host = "203.0.113.10"           # 写进链接和订阅的地址
syn_rewrite_iface = "eth0"             # 出口网卡，挂 eBPF
console_listen = "10.255.0.1:43480"    # 看板，只听内网地址
default_template = "auto"
```

- `99-ssfp.conf` 把 `net.ipv4.tcp_rmem` 上限调到 32 MB：Windows 模板的 wscale 8 需要 ≥ 12 MB，Android 的 wscale 9 需要 ≥ 24 MB，否则内核选出的 wscale 会偏小。
- 防火墙放行 `listen` 端口的 TCP 和 UDP。看板端口不要对外开放。
- 看板地址：可以给 `lo` 加一个只在本机存在的地址（`ip addr add 10.255.0.1/32 dev lo`），客户端经 ssfp 访问这个地址会被放行，外网访问不到。

## 用户、设备、订阅

```sh
ssfp ctl user add 我
ssfp ctl dev add 我 台式机 windows
ssfp ctl dev add 我 MacBook apple
ssfp ctl dev add 我 手机 android
ssfp ctl list                         # 用户、设备、模板、在线连接、今日 / 本月流量
ssfp ctl dev link 我/手机             # 单台设备的 ss:// 链接
ssfp ctl sub 我 --dialer 中转节点     # Clash 订阅内容（第一次导入用）
ssfp ctl url                          # 看板地址（含登录令牌）
```

订阅内容是 Clash 格式，可以整段粘贴，也可以作为 proxy-provider 地址（经 VPN 内网访问）：

```yaml
proxies:
  - {name: "我-台式机", type: ss, server: "203.0.113.10", port: 8388, cipher: 2022-blake3-aes-128-gcm, password: "PSK:设备密钥", udp: true, dialer-proxy: "中转节点"}
  - {name: "我-MacBook", ...}
  - {name: "我-手机", ...}
proxy-groups:
  - {name: "ssfp-我", type: select, proxies: ["我-台式机", "我-MacBook", "我-手机"]}
```

**每台设备选自己名字的节点。** Windows 电脑用了 Mac 的节点，网站就会看到 Mac 的 TCP 指纹配 Windows 浏览器，反而不一致。

设备改动（新增、停用、换模板、换密钥）立即生效，不需要重启；停用和换模板会断开该设备的现有连接。

### 看板

运行 `ssfp ctl url`，在连着 ssfp 的设备上打开输出的地址。看板包含：运行状态与 eBPF 挂载情况、当前连接与速率、今日 / 本月流量；每个用户的设备列表（模板、在线、流量、复制链接、停用、换密钥）、订阅地址与内容、近 7 天按设备的流量、当前连接（可断开）。

### 模板

| 模板 | TTL | SYN 窗口 | wscale | 时间戳 | 选项顺序 |
|---|---|---|---|---|---|
| `windows` | 128 | 65535 | 8 | 无 | MSS,NOP,WS,NOP,NOP,SACK_PERM |
| `apple`（macOS / iOS） | 64 | 65535 | 6 | 有 | MSS,NOP,WS,NOP,NOP,TS,SACK_PERM,EOL |
| `android` | 64 | 65535 | 9 | 有 | MSS,SACK_PERM,TS,NOP,WS |
| `linux` | 64 | 64240 | 7 | 有 | MSS,SACK_PERM,TS,NOP,WS |
| `none` | 不改 | | | | |
| `auto` | 按学到的系统；没学到时按客户端特征（明文 UA、JA4 表、客户端 SYN）判断 | | | | |

`auto` 的学习依据是设备经 ssfp 访问的系统专属域名，例如 `msftconnecttest.com`（Windows 联网检测）、`captive.apple.com`、`connectivitycheck.gstatic.com`。如果客户端规则把这些域名直连，就学不到，直接选系统更可靠。

模板值在 `fpcore/src/template.rs`。想用自己的设备校准：让设备直连访问 `fpprobe`，对照网页上的 SYN 字段修改。

## 检测靶机

靶机已拆成独立项目 [fpprobe](https://github.com/aidever/fpprobe)，提供 Docker 镜像 `ghcr.io/aidever/fpprobe`。网页显示网站能看到的 TCP SYN 与 p0f 判定、TLS JA4、UA、握手 RTT 与应用层 RTT，并判断"TCP 层系统与浏览器自报系统是否一致"。分别直连和经 ssfp 访问一次，就能对比效果。

## 局限

- **只改 SYN 的形状。** IP ID 规律、ACK 窗口变化、时间戳时钟频率、拥塞控制行为仍是 Linux 的，更细的指纹可以区分。
- **RTT 对不上。** 网站量到的 TCP 握手 RTT 是到服务器的，浏览器里量到的应用层 RTT 是到你本人的，这是所有代理的共同特征，TCP 指纹解决不了。
- **MSS 是服务器的**（通常 1460），家宽常见 1412–1492。
- **JA4 分不出系统**：同版本 Chrome 在 Windows / macOS / Android 上 JA4 相同，`[ja4]` 对照表只对 Safari 等少数情况有用。
- 入口和出口是同一个 IP；IPv6 出站路径的 eBPF 改写有实现，未充分测试。
- 模板只用少量真机校准过，不同系统版本、网卡、驱动可能不同。

## 安全提示

- 看板令牌（`/var/lib/ssfp/admin.token`）等同管理员密码；订阅内容包含密钥。看板只应监听内网 / VPN 地址。
- 用户、设备、密钥保存在 `/var/lib/ssfp/state.json`（0600），流量在 `traffic.json`。

## 免责声明

本项目用于网络指纹与隐私研究。请遵守所在地法律法规与服务条款，使用者自行承担责任。

## 许可证

MIT，见 [LICENSE](LICENSE)。eBPF 程序（`server/bpf/syn_rewrite.bpf.c`）为 MIT 或 GPL-2.0 双许可，以便内核加载需要 GPL 的辅助函数。
