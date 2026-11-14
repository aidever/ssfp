//! 部署辅助命令：ssfp init（生成配置）、ssfp check（体检）。
//! 输出固定格式（OK / WARN / FAIL 开头），方便人和 AI 助手读。

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context as _, bail};
use shadowsocks::crypto::CipherKind;

use crate::config::{self, Config};

pub const DEFAULT_CONFIG: &str = "/etc/ssfp/config.toml";

const INIT_HELP: &str = "用法：ssfp init [-c 配置路径] [--port 8388] [--host 公网地址] [--method 2022-blake3-aes-128-gcm] [--force]
生成配置文件（随机服务端 PSK）。已存在时不覆盖，除非加 --force。";

/// 出口网卡上的 IPv4（不发包）
pub fn local_egress_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:53").ok()?;
    Some(s.local_addr().ok()?.ip())
}

pub fn run_init(args: &[String]) -> anyhow::Result<()> {
    let mut path = DEFAULT_CONFIG.to_string();
    let mut port: u16 = 8388;
    let mut host: Option<String> = None;
    let mut method = "2022-blake3-aes-128-gcm".to_string();
    let mut force = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut v = || it.next().cloned().with_context(|| format!("{a} 缺少参数\n{INIT_HELP}"));
        match a.as_str() {
            "-c" => path = v()?,
            "--port" => port = v()?.parse().context("--port 不是端口号")?,
            "--host" => host = Some(v()?),
            "--method" => method = v()?,
            "--force" => force = true,
            "-h" | "--help" => {
                println!("{INIT_HELP}");
                return Ok(());
            }
            _ => bail!("未知参数 {a}\n{INIT_HELP}"),
        }
    }
    let kind: CipherKind = method.parse().map_err(|_| anyhow::anyhow!("不支持的加密方式 {method}"))?;
    anyhow::ensure!(kind.is_aead_2022(), "只支持 SS2022 加密方式（2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm）");
    if Path::new(&path).exists() && !force {
        println!("SKIP 配置已存在：{path}（要重新生成请加 --force，会换掉服务端 PSK，所有链接都要重新导入）");
        return Ok(());
    }
    let psk = crate::store::b64(&crate::store::random_bytes(kind.key_len()));
    let host_line = match &host {
        Some(h) => format!("public_host = \"{h}\""),
        None => {
            let ip = local_egress_ip();
            match ip {
                Some(ip) if crate::net::is_public(ip) => format!("public_host = \"{ip}\""),
                _ => {
                    eprintln!(
                        "WARN 出口网卡地址 {} 不是公网地址（云主机 NAT？），请用 --host 指定公网 IP 或域名，或之后编辑 public_host",
                        ip.map(|i| i.to_string()).unwrap_or_else(|| "?".into())
                    );
                    "# public_host = \"203.0.113.10\"   # 必填：客户端连接用的公网 IP 或域名".into()
                }
            }
        }
    };
    let text = format!(
        r#"# ssfp 配置（由 ssfp init 生成）。完整说明见 https://github.com/aidever/ssfp/blob/main/server/deploy/config.example.toml
listen = "0.0.0.0:{port}"
method = "{method}"
# 服务端 PSK。改了它所有设备的链接都要重新导入
password = "{psk}"
# 写进链接和订阅的服务器地址
{host_line}

# 出口网卡挂 eBPF 改写 SYN：auto = 默认路由网卡，off = 不挂（只改 TTL / wscale）
syn_rewrite_iface = "auto"

# 设备模板为 auto 且还没学到系统时用的模板
default_template = "auto"

udp = true
block_quic = true      # 丢弃 UDP 443（QUIC），浏览器回落到 TCP
block_private = true   # 拒绝经代理访问内网地址

# 管理看板（只听本机，用 SSH 端口转发打开）。用户和设备用看板或 `ssfp ctl` 管理
console_listen = "127.0.0.1:43480"
state_dir = "/var/lib/ssfp"
log = "/var/log/ssfp/conn.jsonl"
"#
    );
    if let Some(dir) = Path::new(&path).parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("创建 {}", dir.display()))?;
    }
    std::fs::write(&path, text).with_context(|| format!("写入 {path}"))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Config::load(&path).context("生成的配置无法解析（bug）")?;
    println!("OK 已生成 {path}（端口 {port}，{method}）");
    Ok(())
}

struct Report {
    fails: usize,
    warns: usize,
}

impl Report {
    fn ok(&mut self, m: impl AsRef<str>) {
        println!("OK   {}", m.as_ref());
    }
    fn warn(&mut self, m: impl AsRef<str>) {
        self.warns += 1;
        println!("WARN {}", m.as_ref());
    }
    fn fail(&mut self, m: impl AsRef<str>) {
        self.fails += 1;
        println!("FAIL {}", m.as_ref());
    }
}

fn read_trim(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// 体检：配置、内核参数、服务状态、eBPF。有 FAIL 时返回错误（退出码 1）
pub async fn run_check(args: &[String]) -> anyhow::Result<()> {
    let path = match args {
        [c, p] if c == "-c" => p.clone(),
        [] => DEFAULT_CONFIG.to_string(),
        _ => bail!("用法：ssfp check [-c 配置路径]"),
    };
    let mut r = Report { fails: 0, warns: 0 };
    println!(
        "ssfp {}，内核 {}，{}",
        env!("CARGO_PKG_VERSION"),
        read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "?".into()),
        std::env::consts::ARCH
    );

    let cfg = match Config::load(&path) {
        Ok(c) => {
            r.ok(format!("配置 {path} 解析通过，监听 {}，{}", c.listen, c.method));
            c
        }
        Err(e) => {
            r.fail(format!("配置 {path}：{e:#}"));
            println!("结果：{} 项失败", r.fails);
            bail!("体检未通过");
        }
    };
    match cfg.method.parse::<CipherKind>() {
        Ok(k) if k.is_aead_2022() => match crate::store::b64_decode(&cfg.password) {
            Some(b) if b.len() == k.key_len() => r.ok("服务端 PSK 长度正确"),
            _ => r.fail(format!("服务端 PSK 应为 {} 字节的 base64（openssl rand -base64 {}）", k.key_len(), k.key_len())),
        },
        _ => r.fail(format!("不支持的加密方式 {}，只支持 SS2022", cfg.method)),
    }

    match &cfg.public_host {
        Some(h) => match h.parse::<IpAddr>() {
            Ok(ip) if !crate::net::is_public(ip) => r.warn(format!("public_host = {h} 不是公网地址，客户端可能连不上")),
            _ => r.ok(format!("public_host = {h}")),
        },
        None => match local_egress_ip() {
            Some(ip) if crate::net::is_public(ip) => r.ok(format!("public_host 未设置，使用出口网卡地址 {ip}")),
            ip => r.warn(format!(
                "public_host 未设置，出口网卡地址 {} 不是公网地址：链接里的服务器地址会是错的，请在配置里填 public_host",
                ip.map(|i| i.to_string()).unwrap_or_else(|| "?".into())
            )),
        },
    }

    match &cfg.syn_rewrite_iface {
        Some(i) if Path::new(&format!("/sys/class/net/{i}")).exists() => {
            r.ok(format!("eBPF 网卡 {i}（L3 偏移 {}）", cfg.syn_rewrite_l3_offset))
        }
        Some(i) => r.fail(format!("eBPF 网卡 {i} 不存在（syn_rewrite_iface）")),
        None => r.warn("未启用 eBPF SYN 改写（syn_rewrite_iface = off，或找不到默认路由网卡）：只改 TTL / wscale"),
    }
    if let Some(i) = &cfg.syn_rewrite_iface {
        if config::default_iface().as_deref().is_some_and(|d| d != i) {
            r.warn(format!("默认路由网卡是 {}，不是 {i}；出站 SYN 不经过 {i} 就不会被改写", config::default_iface().unwrap()));
        }
    }

    let rmem_max = read_trim("/proc/sys/net/ipv4/tcp_rmem")
        .and_then(|s| s.split_whitespace().nth(2).and_then(|v| v.parse::<u64>().ok()))
        .unwrap_or(0);
    if rmem_max >= 25_165_824 {
        r.ok(format!("net.ipv4.tcp_rmem 上限 {rmem_max}"));
    } else {
        r.warn(format!(
            "net.ipv4.tcp_rmem 上限 {rmem_max} < 25165824：Windows / Android 模板的 wscale 会偏小。安装 deploy/99-ssfp.conf 后 sysctl --system"
        ));
    }

    // 服务状态：经看板接口读
    let Some(console) = cfg.console_listen else {
        r.warn("看板已关闭（console_listen），无法检查运行状态");
        return finish(r);
    };
    let token = crate::admin_token(Path::new(&cfg.state_dir)).unwrap_or_default();
    match crate::ctl::get_json(console, &token, "/api/overview").await {
        Ok(v) => {
            r.ok(format!(
                "服务运行中：版本 {}，已运行 {} 秒，{} 个用户 / {} 台设备，当前 {} 个连接",
                v["version"].as_str().unwrap_or("?"),
                v["uptime_s"],
                v["users"],
                v["devices"],
                v["conns"]
            ));
            if v["version"].as_str() != Some(env!("CARGO_PKG_VERSION")) {
                r.warn(format!(
                    "运行中的版本 {} 与本程序 {} 不同，升级后需要 systemctl restart ssfp",
                    v["version"].as_str().unwrap_or("?"),
                    env!("CARGO_PKG_VERSION")
                ));
            }
            match (v["ebpf_iface"].as_str(), v["ebpf_error"].as_str()) {
                (Some(i), _) => r.ok(format!("eBPF SYN 改写已挂到 {i}，计数 {}", v["ebpf_stats"])),
                (None, Some(e)) => r.fail(format!("eBPF SYN 改写没有挂上：{e}")),
                (None, None) => {}
            }
            if v["devices"].as_u64() == Some(0) {
                r.warn("还没有设备：ssfp ctl user add <用户> && ssfp ctl dev add <用户> <设备名> <windows|apple|android|linux>");
            }
        }
        Err(e) => r.fail(format!("服务没有响应（{e:#}）：systemctl status ssfp / journalctl -u ssfp -n 50")),
    }
    finish(r)
}

fn finish(r: Report) -> anyhow::Result<()> {
    if r.fails > 0 {
        println!("结果：{} 项失败，{} 项警告", r.fails, r.warns);
        bail!("体检未通过");
    }
    println!("结果：通过（{} 项警告）", r.warns);
    Ok(())
}
