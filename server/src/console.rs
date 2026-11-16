//! 管理看板 + 订阅（HTTP，只听内网地址）。
//!
//! - GET  /                     看板页面（令牌放在地址 #t=… 里，由页面存到本地）
//! - GET  /s/<用户令牌>          订阅：Clash 格式，proxies + 一个包含该用户所有设备节点的 proxy-group
//! - /api/*                     管理接口，需要 Authorization: Bearer <admin.token>

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use anyhow::Context as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::State;
use crate::config::TemplateChoice;
use crate::store::{self, Device, Learned, User};
use crate::traffic::{Traffic, local_date};

const PAGE: &str = include_str!("console.html");
const TEMPLATES: [&str; 6] = ["auto", "windows", "apple", "android", "linux", "none"];

type Resp = Response<Full<Bytes>>;

fn resp(code: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Resp {
    Response::builder()
        .status(code)
        .header("content-type", ctype)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(body.into()))
        .unwrap()
}

fn json_resp(code: StatusCode, v: Value) -> Resp {
    resp(code, "application/json; charset=utf-8", v.to_string())
}

fn err(code: StatusCode, msg: impl std::fmt::Display) -> Resp {
    json_resp(code, json!({ "error": msg.to_string() }))
}

pub async fn serve(st: Arc<State>, addr: SocketAddr) -> anyhow::Result<()> {
    let l = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("看板绑定 {addr}"))?;
    eprintln!("看板 http://{addr}/ （令牌见 ssfp ctl url）");
    loop {
        let (s, _) = match l.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let st = st.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let st = st.clone();
                async move { Ok::<_, Infallible>(route(st, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(s), svc)
                .await;
        });
    }
}

fn query(req: &Request<Incoming>, key: &str) -> Option<String> {
    req.uri().query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| url_decode(v))
    })
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn authed(st: &State, req: &Request<Incoming>) -> bool {
    let got = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let want = st.admin_token.as_bytes();
    got.len() == want.len() && got.bytes().zip(want).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

async fn body_json<T: for<'de> Deserialize<'de>>(req: Request<Incoming>) -> Result<T, Resp> {
    let b = req.into_body().collect().await.map_err(|e| err(StatusCode::BAD_REQUEST, e))?.to_bytes();
    if b.len() > 65536 {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "请求太大"));
    }
    serde_json::from_slice(&b).map_err(|e| err(StatusCode::BAD_REQUEST, format!("JSON 格式不对: {e}")))
}

async fn route(st: Arc<State>, req: Request<Incoming>) -> Resp {
    let path = req.uri().path().to_string();
    let m = req.method().clone();
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (m.clone(), parts.as_slice()) {
        (Method::GET, [""]) => return resp(StatusCode::OK, "text/html; charset=utf-8", PAGE),
        (Method::GET, ["s", token]) => {
            let uid = st.store.with(|d| d.users.iter().find(|u| u.token == *token && u.enabled).map(|u| u.id));
            return match uid {
                Some(id) => resp(StatusCode::OK, "text/yaml; charset=utf-8", clash_yaml(&st, id, query(&req, "dialer").as_deref())),
                None => err(StatusCode::NOT_FOUND, "订阅不存在或已停用"),
            };
        }
        _ => {}
    }
    if parts.first() != Some(&"api") {
        return err(StatusCode::NOT_FOUND, "没有这个地址");
    }
    if !authed(&st, &req) {
        return err(StatusCode::UNAUTHORIZED, "需要管理令牌：在服务器上运行 ssfp ctl url");
    }
    let r = match (m, &parts[1..]) {
        (Method::GET, ["overview"]) => Ok(json_resp(StatusCode::OK, overview(&st))),
        (Method::GET, ["users"]) => Ok(json_resp(StatusCode::OK, users_json(&st))),
        (Method::GET, ["conns"]) => Ok(json_resp(StatusCode::OK, Value::Array(st.traffic.conns()))),
        (Method::GET, ["history"]) => {
            let days = query(&req, "days").and_then(|d| d.parse().ok()).unwrap_or(7usize).clamp(1, 90);
            let user = query(&req, "user").and_then(|d| d.parse().ok());
            Ok(json_resp(StatusCode::OK, history(&st, days, user)))
        }
        (Method::POST, ["users"]) => add_user(&st, req).await,
        (Method::PATCH, ["users", id]) => patch_user(&st, id.parse().unwrap_or(0), req).await,
        (Method::DELETE, ["users", id]) => del_user(&st, id.parse().unwrap_or(0)),
        (Method::POST, ["users", id, "rotate-token"]) => rotate_token(&st, id.parse().unwrap_or(0)),
        (Method::GET, ["users", id, "clash"]) => {
            let id: u32 = id.parse().unwrap_or(0);
            if st.store.with(|d| d.users.iter().any(|u| u.id == id)) {
                Ok(resp(StatusCode::OK, "text/yaml; charset=utf-8", clash_yaml(&st, id, query(&req, "dialer").as_deref())))
            } else {
                Err(err(StatusCode::NOT_FOUND, "用户不存在"))
            }
        }
        (Method::POST, ["users", id, "devices"]) => add_device(&st, id.parse().unwrap_or(0), req).await,
        (Method::PATCH, ["devices", id]) => patch_device(&st, id.parse().unwrap_or(0), req).await,
        (Method::DELETE, ["devices", id]) => del_device(&st, id.parse().unwrap_or(0)),
        (Method::POST, ["devices", id, "rotate-key"]) => rotate_key(&st, id.parse().unwrap_or(0)),
        (Method::POST, ["conns", id, "close"]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let n = st.traffic.kill(|c| c.id == id);
            Ok(json_resp(StatusCode::OK, json!({ "closed": n })))
        }
        _ => Err(err(StatusCode::NOT_FOUND, "没有这个接口")),
    };
    r.unwrap_or_else(|e| e)
}

// ---------- 订阅 / 链接 ----------

fn node_name(u: &User, d: &Device) -> String {
    format!("{}-{}", u.name, d.name)
}

fn b64url(s: &str) -> String {
    store::b64(s.as_bytes()).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

pub fn ss_link(st: &State, u: &User, d: &Device) -> String {
    let port = st.cfg.listen.port();
    let ui = b64url(&format!("{}:{}:{}", st.cfg.method, st.cfg.password, d.key));
    format!("ss://{ui}@{}:{port}#{}", host_for_uri(&st.public_host), url_encode(&node_name(u, d)))
}

fn host_for_uri(h: &str) -> String {
    if h.contains(':') && !h.starts_with('[') { format!("[{h}]") } else { h.to_string() }
}

fn q(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

pub fn clash_yaml(st: &State, user_id: u32, dialer: Option<&str>) -> String {
    st.store.with(|d| {
        let Some(u) = d.users.iter().find(|u| u.id == user_id) else { return String::new() };
        let devs: Vec<&Device> = d.devices.iter().filter(|x| x.user_id == user_id && x.enabled).collect();
        let mut y = format!(
            "# ssfp 订阅：{}（{} 台设备）\n# 每台设备用自己的节点：出口指纹按该设备的系统模板\nproxies:\n",
            u.name,
            devs.len()
        );
        for dv in &devs {
            let dialer = dialer.filter(|s| !s.is_empty()).map(|s| format!(", dialer-proxy: {}", q(s))).unwrap_or_default();
            y += &format!(
                "  - {{name: {}, type: ss, server: {}, port: {}, cipher: {}, password: {}, udp: true{dialer}}}\n",
                q(&node_name(u, dv)),
                q(&st.public_host),
                st.cfg.listen.port(),
                st.cfg.method,
                q(&format!("{}:{}", st.cfg.password, dv.key)),
            );
        }
        if devs.is_empty() {
            y += "  []\n";
        }
        y += &format!(
            "proxy-groups:\n  - {{name: {}, type: select, proxies: [{}]}}\n",
            q(&format!("ssfp-{}", u.name)),
            devs.iter().map(|dv| q(&node_name(u, dv))).collect::<Vec<_>>().join(", ")
        );
        y
    })
}

// ---------- 查询 ----------

fn overview(st: &State) -> Value {
    let today = vec![local_date(crate::now_ms())];
    let month = Traffic::month_dates();
    let (ids, users, devices) = st.store.with(|d| (d.devices.iter().map(|x| x.id).collect::<Vec<_>>(), d.users.len(), d.devices.len()));
    let sum = |dates: &[String]| {
        ids.iter().chain(std::iter::once(&0)).fold((0u64, 0u64), |a, id| {
            let (u, d) = st.traffic.usage(*id, dates);
            (a.0 + u, a.1 + d)
        })
    };
    let (tu, td) = sum(&today);
    let (mu, md) = sum(&month);
    let online = ids.iter().filter(|id| st.traffic.dev_opt(**id).is_some_and(|s| s.conns.load(Relaxed) > 0)).count();
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": (crate::now_ms() - st.traffic.started_ms) / 1000,
        "listen": st.cfg.listen.to_string(),
        "public_host": st.public_host,
        "console": st.cfg.console_listen.map(|a| a.to_string()),
        "ebpf_iface": st.ebpf_iface.lock().unwrap().clone(),
        "ebpf_error": st.ebpf_error.lock().unwrap().clone(),
        "ebpf_stats": st.ebpf.lock().unwrap().as_ref().map(|r| r.stats_total()),
        "udp": st.cfg.udp,
        "block_quic": st.cfg.block_quic,
        "conns": st.traffic.conn_count(),
        "online_devices": online,
        "rate": st.traffic.rate(),
        "today": {"up": tu, "down": td},
        "month": {"up": mu, "down": md},
        "users": users,
        "devices": devices,
        "templates": TEMPLATES,
    })
}

fn users_json(st: &State) -> Value {
    let today = vec![local_date(crate::now_ms())];
    let month = Traffic::month_dates();
    st.store.with(|d| {
        Value::Array(
            d.users
                .iter()
                .map(|u| {
                    let devs: Vec<Value> = d
                        .devices
                        .iter()
                        .filter(|x| x.user_id == u.id)
                        .map(|x| {
                            let s = st.traffic.dev_opt(x.id);
                            let (tu, td) = st.traffic.usage(x.id, &today);
                            let (mu, md) = st.traffic.usage(x.id, &month);
                            let effective = match TemplateChoice::parse(&x.template) {
                                Ok(TemplateChoice::Fixed(f)) => Some(TemplateChoice::Fixed(f).name()),
                                _ => x.learned.family.map(|f| TemplateChoice::Fixed(f).name()),
                            };
                            json!({
                                "id": x.id, "name": x.name, "template": x.template, "effective": effective,
                                "learned": {"family": x.learned.family, "hint": x.learned.hint, "at_ms": x.learned.at_ms, "hits": x.learned.hits},
                                "enabled": x.enabled, "node": node_name(u, x), "link": ss_link(st, u, x),
                                "conns": s.as_ref().map(|s| s.conns.load(Relaxed)).unwrap_or(0),
                                "last_seen_ms": s.as_ref().map(|s| s.last_seen_ms.load(Relaxed)).unwrap_or(0),
                                "today": {"up": tu, "down": td}, "month": {"up": mu, "down": md},
                                "total": s.as_ref().map(|s| s.up.load(Relaxed) + s.down.load(Relaxed)).unwrap_or(0),
                                "private_allow": x.private_allow,
                                "created_ms": x.created_ms,
                            })
                        })
                        .collect();
                    let sub = st.cfg.console_listen.map(|a| format!("http://{a}/s/{}", u.token));
                    json!({ "id": u.id, "name": u.name, "enabled": u.enabled, "token": u.token, "sub_url": sub,
                            "created_ms": u.created_ms, "devices": devs })
                })
                .collect(),
        )
    })
}

fn history(st: &State, days: usize, user: Option<u32>) -> Value {
    let dates = Traffic::last_days(days);
    let series: Vec<Value> = st.store.with(|d| {
        d.devices
            .iter()
            .filter(|x| user.is_none_or(|u| x.user_id == u))
            .map(|x| {
                let uname = d.users.iter().find(|u| u.id == x.user_id).map(|u| u.name.clone()).unwrap_or_default();
                let vals: Vec<u64> = dates
                    .iter()
                    .map(|day| {
                        let (u, dn) = st.traffic.usage(x.id, std::slice::from_ref(day));
                        u + dn
                    })
                    .collect();
                json!({ "device_id": x.id, "name": x.name, "user": uname, "values": vals })
            })
            .collect()
    });
    json!({ "dates": dates, "series": series })
}

// ---------- 修改 ----------

fn check_name(s: &str) -> Result<String, Resp> {
    let s = s.trim();
    if s.is_empty() || s.chars().count() > 32 || s.chars().any(|c| c.is_control() || c == '/' || c == '"') {
        return Err(err(StatusCode::BAD_REQUEST, "名称要 1–32 个字符，不能包含 / 或引号"));
    }
    Ok(s.to_string())
}

fn check_template(s: &str) -> Result<String, Resp> {
    let s = s.trim().to_ascii_lowercase();
    let s = match s.as_str() {
        "macos" | "mac" | "ios" | "iphone" | "ipad" | "ipados" => "apple".to_string(),
        "win" | "win10" | "win11" => "windows".to_string(),
        _ => s,
    };
    if TEMPLATES.contains(&s.as_str()) { Ok(s) } else { Err(err(StatusCode::BAD_REQUEST, format!("模板只能是 {}", TEMPLATES.join(" / ")))) }
}

fn to_resp<T>(r: anyhow::Result<T>, ok: impl FnOnce(T) -> Value) -> Result<Resp, Resp> {
    match r {
        Ok(v) => Ok(json_resp(StatusCode::OK, ok(v))),
        Err(e) => Err(err(StatusCode::BAD_REQUEST, format!("{e:#}"))),
    }
}

#[derive(Deserialize)]
struct NewUser {
    name: String,
}

async fn add_user(st: &State, req: Request<Incoming>) -> Result<Resp, Resp> {
    let b: NewUser = body_json(req).await?;
    let name = check_name(&b.name)?;
    to_resp(
        st.store.update(|d| {
            anyhow::ensure!(!d.users.iter().any(|u| u.name == name), "已有同名用户");
            let id = d.next_id;
            d.next_id += 1;
            d.users.push(User { id, name: name.clone(), token: store::random_token(), enabled: true, created_ms: crate::now_ms() });
            Ok(id)
        }),
        |id| json!({ "id": id }),
    )
}

#[derive(Deserialize)]
struct PatchUser {
    name: Option<String>,
    enabled: Option<bool>,
}

async fn patch_user(st: &State, id: u32, req: Request<Incoming>) -> Result<Resp, Resp> {
    let b: PatchUser = body_json(req).await?;
    let name = b.name.as_deref().map(check_name).transpose()?;
    let r = st.store.update(|d| {
        if let Some(n) = &name {
            anyhow::ensure!(!d.users.iter().any(|u| u.name == *n && u.id != id), "已有同名用户");
        }
        let u = d.users.iter_mut().find(|u| u.id == id).context("用户不存在")?;
        if let Some(n) = name {
            u.name = n;
        }
        if let Some(e) = b.enabled {
            u.enabled = e;
        }
        Ok(d.devices.iter().filter(|x| x.user_id == id).map(|x| x.id).collect::<Vec<_>>())
    });
    if let (Ok(devs), Some(false)) = (&r, b.enabled) {
        st.traffic.kill(|c| devs.contains(&c.device_id));
    }
    to_resp(r, |_| json!({ "ok": true }))
}

fn del_user(st: &State, id: u32) -> Result<Resp, Resp> {
    let r = st.store.update(|d| {
        anyhow::ensure!(d.users.iter().any(|u| u.id == id), "用户不存在");
        let devs: Vec<u32> = d.devices.iter().filter(|x| x.user_id == id).map(|x| x.id).collect();
        d.users.retain(|u| u.id != id);
        d.devices.retain(|x| x.user_id != id);
        Ok(devs)
    });
    if let Ok(devs) = &r {
        st.traffic.kill(|c| devs.contains(&c.device_id));
        for id in devs {
            st.traffic.forget(*id);
        }
    }
    to_resp(r, |_| json!({ "ok": true }))
}

fn rotate_token(st: &State, id: u32) -> Result<Resp, Resp> {
    to_resp(
        st.store.update(|d| {
            let u = d.users.iter_mut().find(|u| u.id == id).context("用户不存在")?;
            u.token = store::random_token();
            Ok(u.token.clone())
        }),
        |t| json!({ "token": t }),
    )
}

#[derive(Deserialize)]
struct NewDevice {
    name: String,
    #[serde(default)]
    template: Option<String>,
    /// 导入已有密钥（可选）
    #[serde(default)]
    key: Option<String>,
}

async fn add_device(st: &State, user_id: u32, req: Request<Incoming>) -> Result<Resp, Resp> {
    let b: NewDevice = body_json(req).await?;
    let name = check_name(&b.name)?;
    let template = check_template(b.template.as_deref().unwrap_or("auto"))?;
    let key = match b.key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => {
            if store::b64_decode(k).map(|v| v.len()) != Some(st.store.key_len()) {
                return Err(err(StatusCode::BAD_REQUEST, format!("密钥要是 {} 字节的 base64", st.store.key_len())));
            }
            k.to_string()
        }
        None => st.store.new_key(),
    };
    to_resp(
        st.store.update(|d| {
            anyhow::ensure!(d.users.iter().any(|u| u.id == user_id), "用户不存在");
            anyhow::ensure!(!d.devices.iter().any(|x| x.user_id == user_id && x.name == name), "这个用户已有同名设备");
            anyhow::ensure!(!d.devices.iter().any(|x| x.key == key), "密钥已被其他设备使用");
            let id = d.next_id;
            d.next_id += 1;
            d.devices.push(Device {
                id,
                user_id,
                name: name.clone(),
                key: key.clone(),
                template: template.clone(),
                enabled: true,
                private_allow: vec![],
                learned: Learned::default(),
                created_ms: crate::now_ms(),
            });
            Ok(id)
        }),
        |id| json!({ "id": id }),
    )
}

#[derive(Deserialize)]
struct PatchDevice {
    name: Option<String>,
    template: Option<String>,
    enabled: Option<bool>,
    /// 清空自动学习结果
    #[serde(default)]
    reset_learned: bool,
}

async fn patch_device(st: &State, id: u32, req: Request<Incoming>) -> Result<Resp, Resp> {
    let b: PatchDevice = body_json(req).await?;
    let name = b.name.as_deref().map(check_name).transpose()?;
    let template = b.template.as_deref().map(check_template).transpose()?;
    let r = st.store.update(|d| {
        let uid = d.devices.iter().find(|x| x.id == id).map(|x| x.user_id).context("设备不存在")?;
        if let Some(n) = &name {
            anyhow::ensure!(!d.devices.iter().any(|x| x.user_id == uid && x.name == *n && x.id != id), "这个用户已有同名设备");
        }
        let x = d.devices.iter_mut().find(|x| x.id == id).unwrap();
        if let Some(n) = name {
            x.name = n;
        }
        if let Some(t) = template {
            x.template = t;
        }
        if let Some(e) = b.enabled {
            x.enabled = e;
        }
        if b.reset_learned {
            x.learned = Learned::default();
        }
        Ok(())
    });
    // 停用或换模板：断开现有连接，让客户端用新设置重连
    if r.is_ok() && (b.enabled == Some(false) || b.template.is_some()) {
        st.traffic.kill(|c| c.device_id == id);
    }
    to_resp(r, |_| json!({ "ok": true }))
}

fn del_device(st: &State, id: u32) -> Result<Resp, Resp> {
    let r = st.store.update(|d| {
        anyhow::ensure!(d.devices.iter().any(|x| x.id == id), "设备不存在");
        d.devices.retain(|x| x.id != id);
        Ok(())
    });
    if r.is_ok() {
        st.traffic.kill(|c| c.device_id == id);
        st.traffic.forget(id);
    }
    to_resp(r, |_| json!({ "ok": true }))
}

fn rotate_key(st: &State, id: u32) -> Result<Resp, Resp> {
    let key = st.store.new_key();
    let r = st.store.update(|d| {
        let x = d.devices.iter_mut().find(|x| x.id == id).context("设备不存在")?;
        x.key = key.clone();
        Ok(())
    });
    if r.is_ok() {
        st.traffic.kill(|c| c.device_id == id);
    }
    to_resp(r, |_| json!({ "ok": true }))
}
