# ssfp

[![release](https://img.shields.io/github/v/release/aidever/ssfp)](https://github.com/aidever/ssfp/releases)
[![ci](https://github.com/aidever/ssfp/actions/workflows/ci.yml/badge.svg)](https://github.com/aidever/ssfp/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/aidever/ssfp)](LICENSE)

**出口 TCP 指纹跟随设备系统的 Shadowsocks 2022 服务端。** Windows 电脑经它上网，网站看到的是 Windows 的 TCP 连接；Mac 是 Mac 的，安卓是安卓的。

> **English:** ssfp is a Shadowsocks 2022 server whose outbound TCP/IP fingerprint (TTL, window, window scale, SYN option layout, timestamps) matches each client device's OS. Every device gets its own key mapped to an OS template; the SYN option layout is rewritten by a small TC eBPF program. Ships with a web console, a CLI, Clash subscriptions, per-device traffic stats, a one-line installer, and a [deployment guide written for AI assistants](docs/AI_DEPLOY.md).

---

## 为什么需要

普通 SS 服务端替你连接网站时，TCP 连接是服务器的 Linux 内核发起的：TTL 64、窗口 64240、选项顺序 `mss,sok,ts,nop,ws`。浏览器却自报 Windows 或 macOS。网站用被动指纹（p0f 一类）一比，就能看出 TCP 层是 Linux、浏览器说自己是 Windows，这是代理的典型特征。

ssfp 给每台设备一把单独的密钥，按设备的系统发起出站连接。实测（同一台 Linux 服务器出口，靶机为 [fpprobe](https://github.com/aidever/fpprobe)）：

| 设备模板 | 网站看到的 SYN | p0f 判定 |
|---|---|---|
| 普通 SS（不改） | TTL 64 · `mss*44,7:mss,sok,ts,nop,ws` | Linux |
| `windows` | TTL 128 · `65535,8:mss,nop,ws,nop,nop,sok` | Windows 10 |
| `apple` | TTL 64 · `65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1` | Mac OS X |
| `android` | TTL 64 · `65535,9:mss,sok,ts,nop,ws` | Android |
| `linux` | TTL 64 · `mss*44,7:mss,sok,ts,nop,ws` | Linux |

模板取自真机实测（Windows 10/11、macOS、Android 10 上的 Chrome）。

## 快速开始

需要一台能 root 登录的 Linux 服务器（x86_64 或 aarch64，systemd，建议内核 ≥ 5.10）。KVM / 独立服务器可以，OpenVZ / LXC 容器一般加载不了 eBPF。

### 方式一：交给 AI 助手部署

把下面这段发给能执行 SSH 命令的 AI 助手（Claude Code、Codex、Cursor 等），按实际情况改好：

```text
请按照 https://raw.githubusercontent.com/aidever/ssfp/main/docs/AI_DEPLOY.md 的步骤，把 ssfp 部署到我的服务器。
SSH：ssh -p 22 root@203.0.113.10（用我的密钥 ~/.ssh/id_ed25519）
我的设备：Windows 台式机、MacBook、iPhone、安卓手机
可选：监听端口 8388；我的 Clash 用中转节点「中转」作为 dialer-proxy
```

助手会做环境检查、安装、放行防火墙、按设备创建密钥、逐台自测，最后交给你 Clash 配置、每台设备的链接，以及打开看板的方法。[docs/AI_DEPLOY.md](docs/AI_DEPLOY.md) 写明了每一步的命令、预期输出、出错时怎么处理，以及哪些事不许做（例如不改 SSH 配置，不动其他服务和已有的防火墙规则）。

> 把 SSH 权限交给 AI 助手前，建议为它单独生成一把密钥，部署完删掉。

### 方式二：一条命令安装

```sh
curl -fsSL https://raw.githubusercontent.com/aidever/ssfp/main/install.sh | sudo bash -s -- --port 8388 --host 203.0.113.10
```

- `--host`：客户端连接用的公网 IP 或域名，会写进链接。不填时自动取出口网卡地址，云主机 NAT 时取到的是内网地址，务必填写。
- `--open-firewall`：ufw / firewalld 已启用时自动放行端口。云主机还要在控制台安全组放行 **TCP + UDP**。
- 脚本会下载 [Releases](https://github.com/aidever/ssfp/releases) 里的静态程序并校验 SHA256，生成配置（随机 PSK），装好 systemd 服务和内核参数，最后运行一次体检。重复运行即升级。

然后添加设备：

```sh
ssfp ctl user add 我
ssfp ctl dev add 我 台式机 windows
ssfp ctl dev add 我 MacBook apple
ssfp ctl dev add 我 手机 android
ssfp ctl dev test 我/台式机      # 以这台设备的身份经 ssfp 访问一次，检查链路和 SYN 改写
ssfp ctl sub 我                  # 打印 Clash 配置
```

## 在客户端使用

`ssfp ctl sub 我` 输出 Clash（mihomo）格式：每台设备一个节点，外加一个包含全部节点的分组。可以整段并入配置文件：

```yaml
proxies:
  - {name: "我-台式机", type: ss, server: "203.0.113.10", port: 8388, cipher: 2022-blake3-aes-128-gcm, password: "服务端PSK:设备密钥", udp: true}
  - {name: "我-MacBook", ...}
  - {name: "我-手机", ...}
proxy-groups:
  - {name: "ssfp-我", type: select, proxies: ["我-台式机", "我-MacBook", "我-手机"]}
```

**每台设备只用自己名字的节点。** Windows 电脑用了 MacBook 的节点，网站就会看到 Mac 的 TCP 指纹配 Windows 浏览器，反而更可疑。

其他客户端（Shadowrocket、v2rayN、sing-box 等）用单台设备的 `ss://` 链接：`ssfp ctl dev link 我/手机`。

**经中转连接**（例如 Clash 的 `dialer-proxy`）：用 `ssfp ctl sub 我 --dialer 中转节点名`，每个节点都会带上 `dialer-proxy`。中转不影响效果，因为模板由密钥决定，与 ssfp 看到的来源无关。

## 管理

### 命令行

| 命令 | 作用 |
|---|---|
| `ssfp ctl list` | 用户、设备、模板、在线连接、今日 / 本月流量 |
| `ssfp ctl user add/del/enable/disable/rename …` | 用户管理 |
| `ssfp ctl dev add <用户> <设备名> [模板]` | 添加设备，输出链接 |
| `ssfp ctl dev os <设备> <模板>` | 改模板（该设备的连接会断开重连） |
| `ssfp ctl dev rotate <设备>` | 换密钥（旧链接失效） |
| `ssfp ctl dev del/enable/disable/rename/link …` | 其他设备操作 |
| `ssfp ctl dev test <设备> [主机:端口]` | 以该设备身份经本机 ssfp 发一个 HTTP 请求，报告链路和 eBPF 改写结果 |
| `ssfp ctl sub <用户> [--dialer 节点名]` | Clash 配置 |
| `ssfp ctl conns` | 当前连接 |
| `ssfp ctl url` | 看板地址（含登录令牌） |
| `ssfp check` | 体检：配置、PSK、公网地址、网卡、内核参数、服务与 eBPF 状态 |

`<设备>` 写编号或 `用户/设备名`。改动立即生效，不用重启。

### 看板

看板默认只监听服务器本机 `127.0.0.1:43480`，用 SSH 端口转发打开：

```sh
ssh -L 43480:127.0.0.1:43480 root@203.0.113.10
# 另开终端，在服务器上执行 ssfp ctl url，把输出的地址粘到本机浏览器
```

看板可以看运行状态、eBPF 计数、实时速率、今日 / 本月流量，管理用户和设备（改模板、复制链接、停用、换密钥），查看订阅内容、近 7 天按设备的流量和当前连接（可断开）。

想不开 SSH 就用看板，可以让它监听一个只有经代理才能到的地址：给 `lo` 加 `10.255.0.1/32`，把 `console_listen` 设为 `10.255.0.1:43480`。ssfp 会放行到这个地址的连接，外网访问不到。

### 模板

| 模板 | 适用 | TTL | SYN 窗口 | wscale | 时间戳 | 选项顺序 |
|---|---|---|---|---|---|---|
| `windows` | Windows | 128 | 65535 | 8 | 无 | MSS,NOP,WS,NOP,NOP,SACK_PERM |
| `apple` | macOS / iOS / iPadOS | 64 | 65535 | 6 | 有 | MSS,NOP,WS,NOP,NOP,TS,SACK_PERM,EOL |
| `android` | Android | 64 | 65535 | 9 | 有 | MSS,SACK_PERM,TS,NOP,WS |
| `linux` | Linux 桌面 | 64 | 64240 | 7 | 有 | MSS,SACK_PERM,TS,NOP,WS |
| `none` | 不改 | | | | | |
| `auto` | 不确定 / 路由器后多台设备 | 按学到的系统 | | | | |

`auto` 根据设备经 ssfp 访问的系统专属域名学习系统（如 `msftconnecttest.com`、`captive.apple.com`、`connectivitycheck.gstatic.com`）。客户端规则把这些域名设成直连时就学不到，所以知道设备系统时直接选对应模板。

## 运维

| 事项 | 做法 |
|---|---|
| 升级 | 重新运行安装命令。保留配置和数据，旧程序备份为 `/usr/local/bin/ssfp.bak` |
| 回滚 | `mv /usr/local/bin/ssfp.bak /usr/local/bin/ssfp && systemctl restart ssfp` |
| 卸载 | `curl -fsSL https://raw.githubusercontent.com/aidever/ssfp/main/install.sh \| sudo bash -s -- --uninstall`（加 `--purge` 删除配置和数据） |
| 日志 | `journalctl -u ssfp`；连接日志 `/var/log/ssfp/conn.jsonl`（超过 64 MB 轮转） |
| 配置 | `/etc/ssfp/config.toml`，完整说明见 [config.example.toml](server/deploy/config.example.toml)；改后 `systemctl restart ssfp` |
| 数据 | `/var/lib/ssfp/`：`state.json`（用户、设备、密钥）、`traffic.json`、`admin.token` |

### 故障排查

| 现象 | 原因与处理 |
|---|---|
| `ssfp check` 报 eBPF 没有挂上：`Operation not permitted` | 服务器是容器（OpenVZ / LXC / Docker）或内核禁止 BPF。服务仍可用，TTL 和 wscale 仍按模板，只是 SYN 选项布局不改写。换 KVM 机器才能完整生效 |
| `public_host … 不是公网地址` | 云主机 NAT。在配置里填 `public_host = "公网IP或域名"`，然后重启服务 |
| `tcp_rmem 上限 … < 25165824` | 内核参数没生效：`sysctl -p /etc/sysctl.d/99-ssfp.conf`。不处理的话 Windows 和 Android 的 wscale 会偏小 |
| 客户端连不上 | 检查云安全组和系统防火墙是否放行了 TCP + UDP 端口；`ssfp ctl dev test` 能通说明服务本身没问题 |
| `dev test` 报“目标没有可用的公网地址” | 服务器的 DNS 返回了内网或 fake-ip 地址，换成 IP 测试：`ssfp ctl dev test 我/台式机 1.1.1.1:80` |
| SYN 应被改写但 eBPF 计数不变 | 出站流量走的不是挂 eBPF 的网卡（策略路由、WireGuard 出口等），在配置里写明 `syn_rewrite_iface` |

## 工作原理

```mermaid
flowchart LR
  B[浏览器] --> C[Clash / SS 客户端]
  C -- "SS2022（设备密钥）" --> S[ssfp]
  S -- "按设备模板拨号<br/>TTL · wscale · SO_MARK" --> K[Linux 内核]
  K -- "SYN" --> E["eBPF（TC egress）<br/>按 mark 改窗口与选项顺序"]
  E --> W[网站]
```

1. 握手时按用户密钥（SS2022 多用户 EIH）找到设备，确定模板：固定模板 > 自动学到的 > 客户端特征 > 默认。
2. 出站 socket 设置 TTL，用 `TCP_WINDOW_CLAMP` 让内核选出目标 wscale，并打上 `SO_MARK`。
3. 出口网卡 egress 上的 eBPF 程序只处理带这个 mark 的本机 SYN：按模板改写窗口值和选项布局（MSS、wscale、时间戳的值沿用内核的），用 `bpf_skb_change_tail` 调整长度并增量更新校验和。其他包原样放行。
4. 不带时间戳的模板（Windows）在 SYN 里去掉 TS 选项，对端的 SYN-ACK 也就不带 TS，内核自然按无时间戳处理。

另外：首包随连接建立立即发出（没有握手完成后空等的间隔）；默认丢弃 UDP 443（QUIC），让浏览器走 TCP；默认拒绝经代理访问内网地址。

**为什么按密钥区分设备：** 客户端经中转连接时，ssfp 看到的是中转服务器的 SYN；同版本 Chrome 在各系统上的 TLS 指纹（JA4）也相同。真正可靠的设备标识只有密钥本身。

## 局限

- **只改 SYN 的形状。** IP ID 规律、ACK 窗口变化、时间戳时钟频率、拥塞控制仍是 Linux 的，更细致的指纹分析可以区分。
- **RTT 对不上。** 网站测到的 TCP 握手 RTT 是到服务器的，浏览器内测到的应用层 RTT 是到你本人的。所有代理都有这个特征，TCP 指纹解决不了。
- **MSS 是服务器的**（通常 1460），家庭宽带常见 1412–1492。
- 入口和出口是同一个 IP。IPv6 出站的 eBPF 改写已实现，但测试不充分；aarch64 版本已编译，未在真机上验证。
- 模板只用少量真机校准过，不同系统版本、网卡和驱动的指纹可能有差异。可以用 [fpprobe](https://github.com/aidever/fpprobe) 测自己的设备，再改 `fpcore/src/template.rs`。

## 从源码构建

需要 Rust（stable）、clang（编译 eBPF）和内核头文件。Debian / Ubuntu：

```sh
apt install clang linux-libc-dev musl-tools
rustup target add x86_64-unknown-linux-musl
cd server
cargo build --release --target x86_64-unknown-linux-musl   # 静态程序：target/x86_64-unknown-linux-musl/release/ssfp
cargo test --release
```

| 目录 | 内容 |
|---|---|
| `server/` | 服务端：SS2022 中继（`src/main.rs`、`udp.rs`）、eBPF（`bpf/`、`src/ebpf.rs`）、看板（`src/console.*`）、命令行（`src/ctl.rs`、`src/admin.rs`）、部署文件（`deploy/`） |
| `fpcore/` | SYN 解析与指纹模板 |
| `install.sh` | 安装 / 升级 / 卸载脚本 |
| `docs/AI_DEPLOY.md` | 给 AI 助手的部署手册 |
| `tools/ja4_table.py` | 从 fpprobe 访问记录生成 JA4 → 系统对照表（可选） |

打 `v*` 标签后，GitHub Actions 会构建 x86_64 和 aarch64 的静态程序，并发布到 Releases。

## 安全

- 链接和订阅里含有设备密钥，看板令牌（`/var/lib/ssfp/admin.token`）等同管理员密码，都不要公开。
- 看板只监听本机或内网地址，不要映射到公网。
- 设备丢失时用 `ssfp ctl dev rotate` 换密钥或 `dev disable` 停用，现有连接会立即断开。

## 免责声明

本项目用于网络指纹与隐私研究。请遵守所在地法律法规与服务条款，使用者自行承担责任。

## 许可证

MIT，见 [LICENSE](LICENSE)。eBPF 程序（`server/bpf/syn_rewrite.bpf.c`）为 MIT 或 GPL-2.0 双许可，以便内核加载需要 GPL 的辅助函数。
