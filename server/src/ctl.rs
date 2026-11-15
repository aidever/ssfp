//! 命令行管理：通过本机看板接口操作，服务需在运行。
//!
//! ssfp ctl [-c 配置] url | list | conns
//! ssfp ctl user add <名称> | del <用户> | rename <用户> <新名> | enable|disable <用户>
//! ssfp ctl dev add <用户> <设备名> [模板] | del <设备> | rename <设备> <新名>
//!              | os <设备> <模板> | enable|disable <设备> | rotate <设备> | link <设备>
//!              | test <设备> [主机:端口]
//! ssfp ctl sub <用户> [--dialer 节点名]
//!
//! <用户> 可以写名称或编号；<设备> 写编号，或 "用户/设备名"。模板：auto windows apple android linux none

use anyhow::{Context as _, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;

const HELP: &str = "用法：
  ssfp ctl url                              看板地址（含登录令牌）
  ssfp ctl list                             用户、设备、流量
  ssfp ctl conns                            当前连接
  ssfp ctl user add <名称>
  ssfp ctl user del|enable|disable <用户>
  ssfp ctl user rename <用户> <新名称>
  ssfp ctl dev add <用户> <设备名> [模板]    模板：auto windows apple android linux none，默认 auto
  ssfp ctl dev os <设备> <模板>
  ssfp ctl dev del|enable|disable|rotate|link <设备>
  ssfp ctl dev rename <设备> <新名称>
  ssfp ctl dev test <设备> [主机:端口]         以该设备身份经本机 ssfp 访问目标（默认 1.1.1.1:80），检查链路与 SYN 改写
  ssfp ctl sub <用户> [--dialer 节点名]       打印 Clash 订阅内容与订阅地址
<用户> 写名称或编号；<设备> 写编号或 用户/设备名。默认配置 /etc/ssfp/config.toml，用 -c 指定。";

struct Client {
    addr: std::net::SocketAddr,
    token: String,
}

impl Client {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<(u16, String)> {
        let mut s = tokio::net::TcpStream::connect(self.addr)
            .await
            .with_context(|| format!("连不上看板 {}，ssfp 在运行吗？", self.addr))?;
        let b = body.map(|v| v.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            self.addr,
            self.token,
            b.len()
        );
        s.write_all(req.as_bytes()).await?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).await?;
        let text = String::from_utf8_lossy(&out).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        Ok((code, body.to_string()))
    }

    async fn json(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let (code, b) = self.call(method, path, body).await?;
        let v: Value = serde_json::from_str(&b).unwrap_or(Value::String(b));
        if code != 200 {
            bail!("{}", v.get("error").and_then(|e| e.as_str()).unwrap_or(&v.to_string()));
        }
        Ok(v)
    }

    async fn users(&self) -> anyhow::Result<Vec<Value>> {
        Ok(self.json("GET", "/api/users", None).await?.as_array().cloned().unwrap_or_default())
    }

    async fn user_id(&self, s: &str) -> anyhow::Result<u64> {
        let us = self.users().await?;
        us.iter()
            .find(|u| u["name"] == s || u["id"].as_u64().map(|i| i.to_string()) == Some(s.to_string()))
            .and_then(|u| u["id"].as_u64())
            .with_context(|| format!("没有用户 {s}"))
    }

    async fn device(&self, s: &str) -> anyhow::Result<(Value, Value)> {
        let us = self.users().await?;
        for u in &us {
            for d in u["devices"].as_array().into_iter().flatten() {
                let full = format!("{}/{}", u["name"].as_str().unwrap_or(""), d["name"].as_str().unwrap_or(""));
                if d["id"].as_u64().map(|i| i.to_string()) == Some(s.to_string()) || full == s {
                    return Ok((u.clone(), d.clone()));
                }
            }
        }
        bail!("没有设备 {s}（写编号或 用户/设备名）")
    }
}

/// 带令牌 GET 看板接口（ssfp check 也用）
pub async fn get_json(addr: std::net::SocketAddr, token: &str, path: &str) -> anyhow::Result<Value> {
    let c = Client { addr, token: token.to_string() };
    tokio::time::timeout(std::time::Duration::from_secs(5), c.json("GET", path, None)).await.context("超时")?
}

/// 以设备身份经本机 ssfp 发一个 HTTP HEAD，返回 (状态行, eBPF 计数前后差)
async fn self_test(cfg: &Config, c: &Client, dev_id: u64, target: &str) -> anyhow::Result<()> {
    use shadowsocks::ProxyClientStream;
    use shadowsocks::config::{ServerConfig, ServerType};
    use shadowsocks::relay::Address;

    let state = std::path::Path::new(&cfg.state_dir).join("state.json");
    let data: crate::store::Data = serde_json::from_str(&std::fs::read_to_string(&state).with_context(|| format!("读取 {}", state.display()))?)?;
    let dev = data.devices.iter().find(|x| x.id as u64 == dev_id).context("state.json 里没有这台设备")?;
    anyhow::ensure!(dev.enabled, "设备已停用");
    let method: shadowsocks::crypto::CipherKind = cfg.method.parse().map_err(|_| anyhow::anyhow!("加密方式无效"))?;
    let mut svr = cfg.listen;
    if svr.ip().is_unspecified() {
        svr.set_ip(if svr.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
    }
    let sc = ServerConfig::new(svr, format!("{}:{}", cfg.password, dev.key), method).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (host, port) = target.rsplit_once(':').context("目标写成 主机:端口")?;
    let port: u16 = port.parse().context("端口无效")?;
    let addr_ip = host.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>().ok();
    let addr = match host.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>() {
        Ok(ip) => Address::SocketAddress((ip, port).into()),
        Err(_) => Address::DomainNameAddress(host.to_string(), port),
    };
    let stats = |v: &Value, k: &str| v["ebpf_stats"][k].as_u64().unwrap_or(0);
    let before = c.json("GET", "/api/overview", None).await?;

    let ctx = shadowsocks::context::Context::new_shared(ServerType::Local);
    let started = std::time::Instant::now();
    let res = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut s = ProxyClientStream::connect(ctx, &sc, addr).await?;
        let req = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ssfp-selftest\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await?;
        let mut buf = vec![0u8; 512];
        let mut got = Vec::new();
        while !got.contains(&b'\n') && got.len() < 4096 {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        anyhow::Ok(got)
    })
    .await;
    let after = c.json("GET", "/api/overview", None).await?;
    // 服务端记录的原因（连接日志最后一条属于这台设备的记录）
    let reason = || {
        let label = data.users.iter().find(|u| u.id == dev.user_id).map(|u| format!("{}/{}", u.name, dev.name)).unwrap_or_default();
        cfg.log
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| {
                t.lines().rev().take(200).filter_map(|l| serde_json::from_str::<Value>(l).ok()).find(|v| v["user"] == label.as_str())
            })
            .and_then(|v| v["error"].as_str().map(|e| format!("；服务端记录：{e}（解析结果 {}）", v["resolved"])))
            .unwrap_or_else(|| "；服务端原因见 journalctl -u ssfp 或连接日志".into())
    };
    let got = match res {
        Ok(Ok(g)) => g,
        Ok(Err(e)) => bail!("FAIL 经 ssfp 连接 {target} 失败：{e:#}{}", reason()),
        Err(_) => bail!("FAIL 经 ssfp 连接 {target} 超时（15 秒）{}", reason()),
    };
    let line = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
    anyhow::ensure!(!line.is_empty(), "FAIL 目标 {target} 没有返回数据{}", reason());
    println!(
        "OK   以设备 {}（模板 {}）经 ssfp 访问 {target}：{line}（{} ms；收到 HTTP 响应即链路正常，状态码不重要）",
        dev.name,
        dev.template,
        started.elapsed().as_millis()
    );

    if after["ebpf_iface"].is_null() {
        println!("WARN eBPF 未挂载，SYN 选项布局没有改写（ssfp check 查看原因）");
        return Ok(());
    }
    let d = |k: &str| stats(&after, k).saturating_sub(stats(&before, k));
    let (rw, un, fail) = (d("rewritten"), d("unchanged"), d("parse_fail") + d("adjust_fail") + d("store_fail"));
    // 内网 / 本机目标走 lo 等网卡，不经过挂 eBPF 的出口网卡，不检查改写
    let public_target = match &addr_ip {
        Some(ip) => crate::net::is_public(*ip),
        None => true,
    };
    let expect_rewrite = public_target && matches!(dev.template.as_str(), "windows" | "apple" | "android");
    if fail > 0 {
        println!("FAIL eBPF 改写出错 {fail} 次（parse/adjust/store），看 journalctl -u ssfp");
    } else if expect_rewrite && rw == 0 {
        println!("FAIL 模板 {} 的 SYN 应被改写，但 eBPF 计数没有变化：出站可能没走 {}", dev.template, after["ebpf_iface"]);
    } else {
        println!("OK   eBPF：本次改写 {rw} 个 SYN，原样放行 {un} 个");
    }
    Ok(())
}

pub fn human(b: u64) -> String {
    let b = b as f64;
    if b >= 1e9 {
        format!("{:.1} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} KB", b / 1e3)
    } else {
        format!("{b:.0} B")
    }
}

fn tpl_label(d: &Value) -> String {
    let t = d["template"].as_str().unwrap_or("auto");
    if t == "auto" {
        match d["effective"].as_str() {
            Some(e) => format!("auto→{e}"),
            None => "auto（未学到）".into(),
        }
    } else {
        t.into()
    }
}

pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<String> = args.to_vec();
    let mut cfg_path = "/etc/ssfp/config.toml".to_string();
    if args.first().map(String::as_str) == Some("-c") && args.len() > 1 {
        cfg_path = args[1].clone();
        args.drain(..2);
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    if a.is_empty() || a[0] == "help" || a[0] == "-h" || a[0] == "--help" {
        println!("{HELP}");
        return Ok(());
    }
    let cfg = Config::load(&cfg_path)?;
    let addr = cfg.console_listen.context("配置里关掉了看板（console_listen），ctl 需要它")?;
    let token = crate::admin_token(std::path::Path::new(&cfg.state_dir))?;
    let c = Client { addr, token: token.clone() };

    match a.as_slice() {
        ["url"] => {
            println!("http://{addr}/#t={token}");
            if !addr.ip().is_loopback() {
                println!("经 SSH 转发（ssh -L {p}:{addr} 服务器）时打开：http://127.0.0.1:{p}/#t={token}", p = addr.port());
            } else {
                println!("在本机电脑上先运行 ssh -L {p}:{addr} 服务器，再用浏览器打开上面的地址", p = addr.port());
            }
            println!("（令牌等同管理员密码，不要外传）");
        }
        ["list"] => {
            for u in c.users().await? {
                println!(
                    "用户 #{} {}{}  订阅 {}",
                    u["id"],
                    u["name"].as_str().unwrap_or(""),
                    if u["enabled"] == false { "（已停用）" } else { "" },
                    u["sub_url"].as_str().unwrap_or("-")
                );
                for d in u["devices"].as_array().into_iter().flatten() {
                    println!(
                        "  #{:<4} {:<16} {:<18} {:<6} 连接 {:<3} 今日 {:>9}  本月 {:>9}",
                        d["id"].as_u64().unwrap_or(0),
                        d["name"].as_str().unwrap_or(""),
                        tpl_label(d),
                        if d["enabled"] == false { "停用" } else { "启用" },
                        d["conns"],
                        human(d["today"]["up"].as_u64().unwrap_or(0) + d["today"]["down"].as_u64().unwrap_or(0)),
                        human(d["month"]["up"].as_u64().unwrap_or(0) + d["month"]["down"].as_u64().unwrap_or(0)),
                    );
                }
            }
        }
        ["conns"] => {
            let v = c.json("GET", "/api/conns", None).await?;
            for x in v.as_array().into_iter().flatten() {
                println!(
                    "#{:<6} {:<20} {:<9} {:<36} ↑{:>9} ↓{:>9}",
                    x["id"].as_u64().unwrap_or(0),
                    x["device"].as_str().unwrap_or(""),
                    x["template"].as_str().unwrap_or("-"),
                    x["target"].as_str().unwrap_or(""),
                    human(x["up"].as_u64().unwrap_or(0)),
                    human(x["down"].as_u64().unwrap_or(0))
                );
            }
        }
        ["user", "add", name] => {
            let v = c.json("POST", "/api/users", Some(json!({ "name": name }))).await?;
            println!("已添加用户 #{} {name}。下一步：ssfp ctl dev add {name} <设备名> [模板]", v["id"]);
        }
        ["user", op @ ("del" | "enable" | "disable"), u] => {
            let id = c.user_id(u).await?;
            match *op {
                "del" => c.json("DELETE", &format!("/api/users/{id}"), None).await?,
                o => c.json("PATCH", &format!("/api/users/{id}"), Some(json!({ "enabled": o == "enable" }))).await?,
            };
            println!("完成");
        }
        ["user", "rename", u, name] => {
            let id = c.user_id(u).await?;
            c.json("PATCH", &format!("/api/users/{id}"), Some(json!({ "name": name }))).await?;
            println!("完成");
        }
        ["dev", "add", u, name, rest @ ..] => {
            let id = c.user_id(u).await?;
            let tpl = rest.first().copied().unwrap_or("auto");
            let v = c.json("POST", &format!("/api/users/{id}/devices"), Some(json!({ "name": name, "template": tpl }))).await?;
            let (_, d) = c.device(&v["id"].to_string()).await?;
            println!("已添加设备 #{} {u}/{name}（模板 {tpl}）\n链接：{}", v["id"], d["link"].as_str().unwrap_or(""));
        }
        ["dev", "os", d, tpl] => {
            let (_, dv) = c.device(d).await?;
            c.json("PATCH", &format!("/api/devices/{}", dv["id"]), Some(json!({ "template": tpl }))).await?;
            println!("完成（该设备的现有连接已断开，客户端会自动重连）");
        }
        ["dev", "test", d, rest @ ..] => {
            let (_, dv) = c.device(d).await?;
            let target = rest.first().copied().unwrap_or("1.1.1.1:80");
            self_test(&cfg, &c, dv["id"].as_u64().unwrap_or(0), target).await?;
        }
        ["dev", "rename", d, name] => {
            let (_, dv) = c.device(d).await?;
            c.json("PATCH", &format!("/api/devices/{}", dv["id"]), Some(json!({ "name": name }))).await?;
            println!("完成");
        }
        ["dev", op @ ("del" | "enable" | "disable" | "rotate" | "link"), d] => {
            let (_, dv) = c.device(d).await?;
            let id = &dv["id"];
            match *op {
                "del" => {
                    c.json("DELETE", &format!("/api/devices/{id}"), None).await?;
                }
                "rotate" => {
                    c.json("POST", &format!("/api/devices/{id}/rotate-key"), None).await?;
                    let (_, dv) = c.device(&id.to_string()).await?;
                    println!("新链接：{}", dv["link"].as_str().unwrap_or(""));
                    return Ok(());
                }
                "link" => {
                    println!("{}", dv["link"].as_str().unwrap_or(""));
                    return Ok(());
                }
                o => {
                    c.json("PATCH", &format!("/api/devices/{id}"), Some(json!({ "enabled": o == "enable" }))).await?;
                }
            }
            println!("完成");
        }
        ["sub", u, rest @ ..] => {
            let id = c.user_id(u).await?;
            let dialer = match rest {
                ["--dialer", n] => format!("?dialer={}", crate::console::url_encode(n)),
                [] => String::new(),
                _ => bail!("用法：ssfp ctl sub <用户> [--dialer 节点名]"),
            };
            let (code, yaml) = c.call("GET", &format!("/api/users/{id}/clash{dialer}"), None).await?;
            anyhow::ensure!(code == 200, "{yaml}");
            print!("{yaml}");
            let us = c.users().await?;
            if let Some(u) = us.iter().find(|x| x["id"].as_u64() == Some(id)) {
                eprintln!(
                    "\n# 订阅地址（经 VPN 内网访问；后续更新用）：{}{}",
                    u["sub_url"].as_str().unwrap_or("-"),
                    dialer
                );
            }
        }
        _ => {
            println!("{HELP}");
            bail!("看不懂这个命令");
        }
    }
    Ok(())
}
