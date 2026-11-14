//! 命令行管理：通过本机看板接口操作，服务需在运行。
//!
//! ssfp ctl [-c 配置] url | list | conns
//! ssfp ctl user add <名称> | del <用户> | rename <用户> <新名> | enable|disable <用户>
//! ssfp ctl dev add <用户> <设备名> [模板] | del <设备> | rename <设备> <新名>
//!              | os <设备> <模板> | enable|disable <设备> | rotate <设备> | link <设备>
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
            println!("（只在内网 / VPN 里能打开；令牌等同管理员密码）");
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
