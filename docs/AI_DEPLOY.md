# ssfp deployment runbook for AI assistants

You are an AI assistant with shell access. A user has asked you to deploy **ssfp** onto their server over SSH and has pointed you to this file. ssfp is a Shadowsocks 2022 server that makes each client device's outbound TCP fingerprint match the device's OS.

Follow this runbook in order. Every step lists the exact commands, the output to expect, and what to do when the output differs. **Talk to the user in the language they wrote to you in.** ssfp's own output is in Chinese. Lines start with `OK`, `WARN`, `FAIL` or `SKIP`, and this runbook quotes the important Chinese phrases so you can match them.

---

## 0. What "done" means

You are finished when all of the following are true:

1. `systemctl is-active ssfp` prints `active`.
2. `ssfp check` ends with `结果：通过` (0 failures). WARN lines are allowed, but you must have reported each one to the user.
3. Every device the user named exists, and `ssfp ctl dev test <user>/<device>` printed `OK` lines for it.
4. You gave the user the final report described in [step 8](#8-report-to-the-user).

---

## 1. Inputs

Take these from the user's message. Ask only for what is missing **and required**.

| Input | Required | Default if not given |
|---|---|---|
| SSH target (host, port, user, key or password) | yes | — |
| Device list (name + OS for each) | yes | — If the user gave none, ask. If they say "just one", create one device with template `auto`. |
| Listen port | no | `8388`. If it is taken, use the first free port from `8388, 8389, 18388, 28388`. |
| Public address for clients | no | The SSH host, **if** it is a public IP or a domain. If it is a private or VPN address (10.x, 172.16–31.x, 192.168.x, 100.64–127.x, fd00::/8), ask the user. |
| User name inside ssfp | no | `me`, or the user's own name/handle if they gave one. |
| Clash `dialer-proxy` node name | no | none |

Map each device's OS to a template:

| Device OS | Template |
|---|---|
| Windows | `windows` |
| macOS, iOS, iPadOS | `apple` |
| Android (phones, tablets, Android TV) | `android` |
| Linux desktop | `linux` |
| Router, unknown, or "several devices share this one" | `auto` |

Device names may contain CJK characters and spaces, but **not** `/`. Keep them short and recognizable, e.g. `desktop`, `macbook`, `iphone`, `pixel`.

---

## 2. Ground rules (do not break these)

1. **Do not touch anything unrelated to ssfp.** Never stop, restart or reconfigure other services (other proxies such as Xray/sing-box/ss-rust, web servers, Docker containers). Never edit `sshd_config`, users, or keys.
2. **Firewall changes are additive only.** You may add an allow rule for the ssfp port (TCP + UDP) on a firewall that is *already active* (ufw / firewalld). Never enable an inactive firewall, never flush or replace rules, never change default policies. If the host uses raw nftables/iptables rules, show the user the exact rule you want to add and wait for approval before running it.
3. **No port scanning**, no load tests, no connections to third-party hosts except GitHub (download) and the self-test target.
4. **Secrets:** `ss://` links, the Clash config, the server PSK and the console token are credentials. Give them only to the user in your final reply. Never put them into commits, issues, pastebins or other tools.
5. **Never run `ssfp init --force` and never edit `password =` in `/etc/ssfp/config.toml`** on an existing install. That rotates the server PSK and breaks every existing client. Re-running `install.sh` is safe: it keeps the config and data.
6. If the same step fails twice, stop. Show the user the command and its output, and propose a fix. Do not improvise destructive workarounds.
7. Do not reboot the server.

---

## 3. Preflight (read-only)

Run this as one command over SSH (prefix with `sudo` if the login user is not root):

```sh
set -x
uname -m; uname -r
cat /etc/os-release | head -3
systemd-detect-virt || true
systemd-detect-virt -c || true
[ -d /run/systemd/system ] && echo SYSTEMD_OK
command -v ssfp && ssfp version && systemctl is-active ssfp
ss -lntup | grep -E ':(8388|8389|18388|28388)\b' || echo PORTS_FREE
ufw status 2>/dev/null | head -1; firewall-cmd --state 2>/dev/null; nft list ruleset 2>/dev/null | head -5
ip -4 route get 1.1.1.1 | head -1
curl -sSI -m 10 https://github.com | head -1
```

Interpret the results:

| Check | Good | Otherwise |
|---|---|---|
| `uname -m` | `x86_64` or `aarch64` | Unsupported architecture: stop and tell the user. |
| `uname -r` | ≥ 5.10 (tested on 6.8) | Older kernels may fail to load the eBPF program. Continue; `ssfp check` will tell you. |
| `systemd-detect-virt` | `kvm`, `microsoft`, `vmware`, `xen`, `amazon`, `none` … | If `-c` prints `openvz`, `lxc`, `docker` etc., eBPF almost certainly will not load. Tell the user that ssfp will only partly work here (TTL and wscale only, no SYN option layout) and ask whether to continue. |
| `SYSTEMD_OK` printed | yes | No systemd: stop. The installer needs systemd. |
| `command -v ssfp` | nothing (fresh install) | Already installed: this is an **upgrade**. Keep the existing config and skip `--port`/`--host` (they are ignored anyway). |
| Ports | `PORTS_FREE`, or your chosen port not listed | Pick the next free candidate port. |
| Firewall | Note which one is active. | — |
| `ip route get` | Its `src` address tells you whether the server is behind NAT. | If `src` is private and the user gave no public address, the SSH host is probably the public address. |
| GitHub | `HTTP/2 200` (or a 301) | No GitHub access: use the [offline install](#offline-install). |

---

## 4. Install

```sh
curl -fsSL https://raw.githubusercontent.com/aidever/ssfp/main/install.sh | sudo bash -s -- --port <PORT> --host <PUBLIC_ADDRESS> --open-firewall
```

- `--open-firewall` only acts on an **already active** ufw / firewalld, which rule 2 allows. If neither is active, it does nothing.
- The installer downloads the release tarball, verifies its SHA256, installs `/usr/local/bin/ssfp`, the systemd unit, `/etc/sysctl.d/99-ssfp.conf`, and creates `/etc/ssfp/config.toml` with a random PSK (fresh install only). It then starts the service and runs `ssfp check`.

Expected tail of the output:

```
==> 安装 ssfp X.Y.Z
OK 已生成 /etc/ssfp/config.toml（端口 <PORT>，2022-blake3-aes-128-gcm）     # fresh install only
...
结果：通过（N 项警告）            # "WARN 还没有设备" is expected at this point
完成。云主机还需要在控制台的安全组里放行 TCP + UDP <PORT>。
```

If it ends with `FAIL 服务没有起来`, read the journal lines it printed and see [troubleshooting](#9-troubleshooting).

### Offline install

When the server cannot reach GitHub, download `ssfp-<arch>-linux-musl.tar.gz` and `install.sh` from https://github.com/aidever/ssfp/releases/latest on the machine you are running on. Copy both to the server with `scp`, then run:

```sh
sudo bash install.sh --file ssfp-<arch>-linux-musl.tar.gz --port <PORT> --host <PUBLIC_ADDRESS> --open-firewall
```

---

## 5. Cloud firewall / security group

You cannot change cloud provider security groups from the server. Tell the user plainly:

> Please allow inbound **TCP and UDP** on port `<PORT>` in your cloud provider's security group / firewall panel (AWS Security Group, GCP VPC firewall, Alibaba Cloud / Tencent Cloud security group, Oracle Cloud security list, etc.). If your provider has none, ignore this.

Do not ask the user to open the console port (43480). The console must stay private.

---

## 6. Create the user and devices

```sh
sudo ssfp ctl user add <USER>
sudo ssfp ctl dev add <USER> <DEVICE> <TEMPLATE>      # once per device
sudo ssfp ctl list
```

`dev add` prints `已添加设备 #<id> <USER>/<DEVICE>（模板 <TEMPLATE>）` and an `ss://` link. On an upgrade where the user already exists, `user add` fails with `已有同名用户` (duplicate name). That is fine: just add the missing devices. Check what exists with `ssfp ctl list` first.

---

## 7. Verify

```sh
sudo ssfp check
sudo ssfp ctl dev test <USER>/<DEVICE>                # once per device
```

**`ssfp check`** must end with `结果：通过`. Meaning of key lines:

| Line | Meaning |
|---|---|
| `OK   eBPF SYN 改写已挂到 <iface>，计数 {...}` | Full fingerprinting is active. |
| `FAIL eBPF SYN 改写没有挂上：…` | The SYN rewrite is not active. See troubleshooting. |
| `WARN public_host … 不是公网地址` | Links would point at a private address. Fix before delivering links. |
| `WARN net.ipv4.tcp_rmem 上限 …` | The Windows/Android window scale will be too small. Run `sudo sysctl -p /etc/sysctl.d/99-ssfp.conf`, then re-check. |
| `WARN 还没有设备` | Go back to step 6. |

**`ssfp ctl dev test`** connects to the local ssfp *as that device* and sends `HEAD /` to `example.com:80`. Expected:

```
OK   以设备 <DEVICE>（模板 windows）经 ssfp 访问 example.com:80：HTTP/1.1 200 OK（123 ms）
OK   eBPF：本次改写 1 个 SYN，原样放行 0 个（linux / none 模板不需要改写）
```

- For `windows` / `apple` / `android`, "改写" (rewritten) must be ≥ 1. For `linux` / `none` / `auto`, 0 rewrites is normal.
- If you see `目标没有可用的公网地址` (the target has no public address), the server's DNS returns private or fake-ip answers. Retest with an IP: `ssfp ctl dev test <USER>/<DEVICE> 1.1.1.1:80` (any HTTP status line counts as success), and mention the DNS issue to the user.

Optional external check: if the user runs an [fpprobe](https://github.com/aidever/fpprobe) instance, they can open it through each device's node and compare the p0f verdict with the device's OS.

---

## 8. Report to the user

Collect the deliverables:

```sh
sudo ssfp ctl sub <USER>                              # add --dialer <NODE> if the user gave a dialer-proxy node
sudo ssfp ctl dev link <USER>/<DEVICE>                # once per device, for non-Clash clients
sudo ssfp ctl url                                     # console URL with token
```

Then reply with this structure (in the user's language):

1. **Status:** version, port, public address, whether eBPF SYN rewriting is active, plus any WARN lines and what they mean.
2. **Action needed from the user:** open TCP + UDP `<PORT>` in the cloud security group (if applicable), and anything else still open.
3. **Clash config:** the full output of `ssfp ctl sub` in a `yaml` code block, with the instruction: *"Merge `proxies` and `proxy-groups` into your config. **On each device, select only the node with that device's name.** Using another device's node makes the fingerprint inconsistent."*
4. **Per-device links** (`ss://…`) for Shadowrocket / v2rayN / sing-box and similar clients, one line per device, labelled.
5. **Console:** `ssh -L 43480:127.0.0.1:43480 <ssh target>`, then open the URL from `ssfp ctl url` in a local browser. Say that the token in the URL is an admin password.
6. **Everyday commands:** `ssfp ctl list`, `ssfp ctl dev add …`, `ssfp ctl dev rotate …`, and upgrading by re-running the install command.
7. A reminder to remove the SSH key they gave you if it was created only for this job.

---

## 9. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `FAIL eBPF SYN 改写没有挂上：… Operation not permitted` | Container virtualization (OpenVZ/LXC), kernel lockdown, or missing BPF support | Check `systemd-detect-virt -c` and `cat /sys/kernel/security/lockdown 2>/dev/null`. If it is a container, it cannot be fixed from inside. Tell the user that only TTL and wscale are applied; full results need a KVM/bare-metal server. Do **not** try to load kernel modules or change boot parameters. |
| `FAIL eBPF … 挂到 <iface> egress 失败` | Wrong interface | Run `ip route get 1.1.1.1` to find the egress interface, set `syn_rewrite_iface = "<iface>"` in `/etc/ssfp/config.toml`, then `systemctl restart ssfp`. |
| `FAIL eBPF 网卡 <iface> 不存在` | Interface name in config is wrong | Same as above. |
| eBPF active, but `dev test` shows 0 rewrites for windows/apple/android | Outbound traffic leaves through another interface (policy routing, WireGuard/WARP egress) | Set `syn_rewrite_iface` to the interface used by `ip route get 1.1.1.1 mark 0x5f500001`, then restart. |
| `FAIL 服务没有响应` | Service crashed or the port is taken | `journalctl -u ssfp -n 50 --no-pager`. "Address already in use" → change `listen` port in config, restart, and update firewall rules accordingly. |
| `FAIL 配置 …` | TOML syntax error | Show the user the error. Fix only the line it names. |
| `下载失败` | No GitHub access | Use the [offline install](#offline-install). |
| `sysctl: permission denied` | Container | Report it. The Windows/Android wscale will be smaller than real devices. |
| Client cannot connect, but `dev test` works | Cloud security group or client-side issue | Re-check step 5. Confirm that the client uses `2022-blake3-aes-128-gcm` and the full `PSK:devicekey` password from the link. |

---

## 10. Reference

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/ssfp` (previous version kept as `ssfp.bak`) |
| Config | `/etc/ssfp/config.toml` (annotated example: `/etc/ssfp/config.example.toml`) |
| Data | `/var/lib/ssfp/state.json` (users, devices, keys), `traffic.json`, `admin.token` |
| Logs | `journalctl -u ssfp`, `/var/log/ssfp/conn.jsonl` |
| Service | `systemctl {status,restart} ssfp` |
| Console | `127.0.0.1:43480` (local only) |
| Upgrade | Re-run the install command |
| Roll back | `mv /usr/local/bin/ssfp.bak /usr/local/bin/ssfp && systemctl restart ssfp` |
| Uninstall | `curl -fsSL https://raw.githubusercontent.com/aidever/ssfp/main/install.sh \| sudo bash -s -- --uninstall` (add `--purge` to delete config and data; ask the user first) |
| All CLI commands | `ssfp help`, `ssfp ctl help` |
