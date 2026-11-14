//! fpprobe：SS 出口指纹检测靶机。
//!
//! - 被动抓包记录 SYN / SYN-ACK / ACK / 首包（capture.rs）
//! - 自己终结 TLS，从原始字节解析 ClientHello 得到 JA4
//! - 网页里用 JS 测应用层 RTT，与 TCP 握手 RTT 对比
//! - 每次访问追加一行 JSONL

mod analyze;
mod capture;

use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls;

use analyze::{OsGuess, Verdict};
use capture::{Flow, FlowTable, now_ns};

const INDEX_HTML: &str = include_str!("../web/index.html");
const CLIENT_HELLO_LIMIT: usize = 16 * 1024;

struct Args {
    iface: String,
    bind: String,
    tls_port: u16,
    http_port: u16,
    cert: Option<String>,
    key: Option<String>,
    log: String,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut a = Args {
        iface: "eth0".into(),
        bind: "0.0.0.0".into(),
        tls_port: 8443,
        http_port: 8080,
        cert: None,
        key: None,
        log: "/var/lib/fpprobe/visits.jsonl".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().with_context(|| format!("{k} 缺少参数"));
        match k.as_str() {
            "--iface" => a.iface = v()?,
            "--bind" => a.bind = v()?,
            "--tls-port" => a.tls_port = v()?.parse()?,
            "--http-port" => a.http_port = v()?.parse()?,
            "--cert" => a.cert = Some(v()?),
            "--key" => a.key = Some(v()?),
            "--log" => a.log = v()?,
            "-h" | "--help" => {
                println!(
                    "fpprobe [--iface eth0] [--bind 0.0.0.0] [--tls-port 8443] [--http-port 8080] \
                     [--cert fullchain.pem --key key.pem] [--log visits.jsonl]"
                );
                std::process::exit(0);
            }
            _ => anyhow::bail!("未知参数 {k}"),
        }
    }
    Ok(a)
}

// ---------- 连接上下文 ----------

#[derive(Debug, Clone, Serialize, Default)]
struct TlsInfo {
    ja4: Option<String>,
    ja4_raw: Option<String>,
    version: Option<String>,
    sni: Option<String>,
    alpn_offered: Option<String>,
    alpn_negotiated: Option<String>,
    cipher_count: usize,
    extension_count: usize,
    client_hello_len: usize,
    parse_error: Option<String>,
}

struct ConnCtx {
    peer: SocketAddr,
    transport: &'static str,
    /// accept 返回的时间（Unix 纳秒），与抓包时间同一时钟
    accepted_at: u64,
    kernel_rtt_ms: Option<f64>,
    tls: Option<TlsInfo>,
}

fn kernel_rtt_ms(fd: i32) -> Option<f64> {
    unsafe {
        let mut info: libc::tcp_info = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let r = libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, &mut info as *mut _ as *mut libc::c_void, &mut len);
        (r == 0 && info.tcpi_rtt > 0).then(|| info.tcpi_rtt as f64 / 1000.0)
    }
}

/// 记录读到的前若干字节（即 ClientHello），写方向直接透传。
struct Tee {
    inner: TcpStream,
    /// 握手完成后置为 None，不再记录
    rec: Arc<Mutex<Option<Vec<u8>>>>,
}

impl AsyncRead for Tee {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            if let Some(rec) = self.rec.lock().unwrap().as_mut() {
                let room = CLIENT_HELLO_LIMIT.saturating_sub(rec.len());
                let new = &buf.filled()[before..];
                rec.extend_from_slice(&new[..new.len().min(room)]);
            }
        }
        r
    }
}

impl AsyncWrite for Tee {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn tls_info(raw: &[u8]) -> TlsInfo {
    let mut t = TlsInfo { client_hello_len: raw.len(), ..Default::default() };
    match huginn_net_tls::parse_tls_client_hello(raw) {
        Ok(sig) => {
            let ja4 = sig.generate_ja4();
            t.ja4 = Some(ja4.full.value().to_string());
            t.ja4_raw = Some(ja4.raw.value().to_string());
            t.version = Some(format!("{:?}", sig.version));
            t.sni = sig.sni.clone();
            t.alpn_offered = sig.alpn.clone();
            t.cipher_count = sig.cipher_suites.len();
            t.extension_count = sig.extensions.len();
        }
        Err(e) => t.parse_error = Some(e.to_string()),
    }
    t
}

// ---------- 报告 ----------

#[derive(Debug, Clone, Serialize, Default)]
struct HttpInfo {
    version: String,
    user_agent: Option<String>,
    sec_ch_ua: Option<String>,
    sec_ch_ua_platform: Option<String>,
    sec_ch_ua_mobile: Option<String>,
    accept_language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClientSide {
    #[serde(default)]
    rtt_samples_ms: Vec<f64>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    languages: Option<Vec<String>>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Timing {
    handshake_rtt_ms: Option<f64>,
    kernel_rtt_ms: Option<f64>,
    ack_to_first_data_ms: Option<f64>,
    syn_retrans_ms: Vec<f64>,
    app_rtt_ms: Option<f64>,
    /// 从收到 ACK 到应用 accept() 返回的耗时
    ack_to_accept_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    id: String,
    at: String,
    at_unix_ms: u64,
    peer: SocketAddr,
    transport: &'static str,
    tcp: Option<Flow>,
    tls: Option<TlsInfo>,
    http: HttpInfo,
    os_tcp: OsGuess,
    os_http: OsGuess,
    timing: Timing,
    verdict: Verdict,
    client: Option<ClientSide>,
}

impl Report {
    fn recompute(&mut self) {
        self.timing.app_rtt_ms = self
            .client
            .as_ref()
            .and_then(|c| c.rtt_samples_ms.iter().copied().filter(|v| v.is_finite() && *v >= 0.0).reduce(f64::min));
        let tcp_rtt = self.timing.handshake_rtt_ms.or(self.timing.kernel_rtt_ms);
        self.verdict = analyze::verdict(&self.os_tcp, &self.os_http, tcp_rtt, self.timing.app_rtt_ms, self.timing.ack_to_first_data_ms);
    }
}

struct State {
    flows: FlowTable,
    pending: Mutex<HashMap<String, (Report, u64)>>,
    recent: Mutex<Vec<serde_json::Value>>,
    log: Mutex<std::fs::File>,
    seq: std::sync::atomic::AtomicU64,
}

impl State {
    fn write(&self, r: &Report) {
        if let Ok(line) = serde_json::to_string(r) {
            let mut f = self.log.lock().unwrap();
            let _ = writeln!(f, "{line}");
        }
        let mut recent = self.recent.lock().unwrap();
        recent.push(serde_json::to_value(r).unwrap_or_default());
        let len = recent.len();
        if len > 500 {
            recent.drain(..len - 500);
        }
    }
}

fn iso_now() -> String {
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil_from_days
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn header(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn build_report(state: &State, ctx: &ConnCtx, req: &Request<Incoming>) -> Report {
    let flow = state.flows.lock().unwrap().get(&ctx.peer).cloned();
    let http = HttpInfo {
        version: format!("{:?}", req.version()),
        user_agent: header(req, "user-agent"),
        sec_ch_ua: header(req, "sec-ch-ua"),
        sec_ch_ua_platform: header(req, "sec-ch-ua-platform"),
        sec_ch_ua_mobile: header(req, "sec-ch-ua-mobile"),
        accept_language: header(req, "accept-language"),
    };
    let os_tcp = flow.as_ref().map(analyze::tcp_os).unwrap_or_else(|| analyze::tcp_os(&Flow::default()));
    let os_http = analyze::http_os(http.user_agent.as_deref(), http.sec_ch_ua_platform.as_deref());
    let timing = Timing {
        handshake_rtt_ms: flow.as_ref().and_then(Flow::handshake_rtt_ms),
        kernel_rtt_ms: ctx.kernel_rtt_ms,
        ack_to_first_data_ms: flow.as_ref().and_then(Flow::ack_to_data_ms),
        syn_retrans_ms: flow
            .as_ref()
            .map(|f| f.syn_retrans_at.iter().filter_map(|t| Some((t - f.syn_at?) as f64 / 1e6)).collect())
            .unwrap_or_default(),
        app_rtt_ms: None,
        ack_to_accept_ms: flow
            .as_ref()
            .and_then(|f| f.ack_at)
            .and_then(|a| ctx.accepted_at.checked_sub(a))
            .map(|d| d as f64 / 1e6),
    };
    let n = state.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut r = Report {
        id: format!("{:x}{:04x}", now_ns() / 1_000_000, n & 0xffff),
        at: iso_now(),
        at_unix_ms: now_ns() / 1_000_000,
        peer: ctx.peer,
        transport: ctx.transport,
        tcp: flow,
        tls: ctx.tls.clone(),
        http,
        os_tcp,
        os_http,
        timing,
        verdict: analyze::verdict(&analyze::tcp_os(&Flow::default()), &analyze::http_os(None, None), None, None, None),
        client: None,
    };
    r.recompute();
    r
}

type Resp = Response<Full<Bytes>>;

fn json<T: Serialize>(status: StatusCode, v: &T) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(serde_json::to_vec_pretty(v).unwrap_or_default())))
        .unwrap()
}

async fn handle(req: Request<Incoming>, ctx: Arc<ConnCtx>, state: Arc<State>) -> Result<Resp, hyper::Error> {
    let path = req.uri().path().to_string();
    let resp = match (req.method(), path.as_str()) {
        (&Method::GET, "/") => {
            let wants_html = header(&req, "accept").is_some_and(|a| a.contains("text/html"));
            if wants_html {
                Response::builder()
                    .header("content-type", "text/html; charset=utf-8")
                    .header("cache-control", "no-store")
                    // 让 Chromium 在后续请求带上完整平台信息
                    .header("accept-ch", "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version")
                    .body(Full::new(Bytes::from_static(INDEX_HTML.as_bytes())))
                    .unwrap()
            } else {
                // curl 等命令行访问直接返回报告并写日志
                let r = build_report(&state, &ctx, &req);
                state.write(&r);
                json(StatusCode::OK, &r)
            }
        }
        (&Method::GET, "/api/me") => {
            let r = build_report(&state, &ctx, &req);
            state.pending.lock().unwrap().insert(r.id.clone(), (r.clone(), now_ns()));
            json(StatusCode::OK, &r)
        }
        (&Method::GET, "/ping") => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        (&Method::POST, "/api/report") => {
            let id = req.uri().query().and_then(|q| q.strip_prefix("id=")).unwrap_or("").to_string();
            let body = req.into_body().collect().await?.to_bytes();
            if body.len() > 64 * 1024 {
                return Ok(json(StatusCode::PAYLOAD_TOO_LARGE, &"too large"));
            }
            let client: ClientSide = serde_json::from_slice(&body).unwrap_or_default();
            let taken = state.pending.lock().unwrap().remove(&id);
            match taken {
                Some((mut r, _)) if r.peer.ip() == ctx.peer.ip() => {
                    r.client = Some(client);
                    r.recompute();
                    state.write(&r);
                    json(StatusCode::OK, &r)
                }
                _ => json(StatusCode::NOT_FOUND, &"unknown id"),
            }
        }
        (&Method::GET, "/api/recent") => {
            // 只返回同一来源 IP 的历史，避免把其他访客暴露出去
            let ip = ctx.peer.ip();
            let ip = ip.to_string();
            let same_ip = |r: &&serde_json::Value| {
                r.get("peer").and_then(|p| p.as_str()).and_then(|p| p.parse::<SocketAddr>().ok()).is_some_and(|p| p.ip().to_string() == ip)
            };
            let list: Vec<serde_json::Value> =
                state.recent.lock().unwrap().iter().rev().filter(same_ip).take(20).cloned().collect();
            json(StatusCode::OK, &list)
        }
        _ => json(StatusCode::NOT_FOUND, &"not found"),
    };
    Ok(resp)
}

async fn serve<S>(io: S, ctx: ConnCtx, state: Arc<State>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ctx = Arc::new(ctx);
    let svc = hyper::service::service_fn(move |req| handle(req, ctx.clone(), state.clone()));
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

// ---------- TLS 配置（证书由外部（Caddy / certbot 等）续期，这里定时重载） ----------

fn load_tls(cert: &str, key: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .context("私钥文件里没有私钥")?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn mtime(p: &str) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    if let Some(dir) = std::path::Path::new(&args.log).parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&args.log).with_context(|| format!("打开日志 {}", args.log))?;
    // 重启后从日志恢复最近 500 条，供历史列表使用
    let recent: Vec<serde_json::Value> = std::fs::read_to_string(&args.log)
        .unwrap_or_default()
        .lines()
        .rev()
        .take(500)
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let flows: FlowTable = Arc::new(Mutex::new(HashMap::new()));

    let cap = capture::Capture::open(&args.iface, args.tls_port, args.http_port, flows.clone())?;
    std::thread::Builder::new().name("capture".into()).spawn(move || cap.run())?;

    let state = Arc::new(State {
        flows,
        pending: Mutex::new(HashMap::new()),
        recent: Mutex::new(recent),
        log: Mutex::new(log),
        seq: Default::default(),
    });

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move {
        // 超过 60 秒没收到 JS 回报的访问，按已有数据落盘
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let cutoff = now_ns().saturating_sub(60_000_000_000);
                let stale: Vec<Report> = {
                    let mut p = st.pending.lock().unwrap();
                    let ids: Vec<String> = p.iter().filter(|(_, (_, t))| *t < cutoff).map(|(k, _)| k.clone()).collect();
                    ids.into_iter().filter_map(|k| p.remove(&k)).map(|(r, _)| r).collect()
                };
                for r in stale {
                    st.write(&r);
                }
            }
        });

        let plain = TcpListener::bind((args.bind.as_str(), args.http_port)).await?;
        eprintln!("HTTP  监听 {}:{}", args.bind, args.http_port);
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, peer)) = plain.accept().await else { continue };
                let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
                let ctx = ConnCtx { peer, transport: "http", accepted_at: now_ns(), kernel_rtt_ms: kernel_rtt_ms(fd), tls: None };
                tokio::spawn(serve(sock, ctx, st.clone()));
            }
        });

        if let (Some(cert), Some(key)) = (args.cert.clone(), args.key.clone()) {
            let cfg = Arc::new(RwLock::new(load_tls(&cert, &key)?));
            let watched = cfg.clone();
            let (c2, k2) = (cert.clone(), key.clone());
            tokio::spawn(async move {
                let mut last = mtime(&c2);
                loop {
                    tokio::time::sleep(Duration::from_secs(600)).await;
                    let m = mtime(&c2);
                    if m != last {
                        match load_tls(&c2, &k2) {
                            Ok(c) => {
                                *watched.write().unwrap() = c;
                                last = m;
                                eprintln!("已重载证书");
                            }
                            Err(e) => eprintln!("重载证书失败: {e}"),
                        }
                    }
                }
            });
            let tls = TcpListener::bind((args.bind.as_str(), args.tls_port)).await?;
            eprintln!("HTTPS 监听 {}:{}", args.bind, args.tls_port);
            loop {
                let Ok((sock, peer)) = tls.accept().await else { continue };
                let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
                let accepted_at = now_ns();
                let krtt = kernel_rtt_ms(fd);
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg.read().unwrap().clone());
                let st = state.clone();
                tokio::spawn(async move {
                    let rec = Arc::new(Mutex::new(Some(Vec::with_capacity(2048))));
                    let tee = Tee { inner: sock, rec: rec.clone() };
                    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tee)).await else { return };
                    let raw = rec.lock().unwrap().take().unwrap_or_default();
                    let mut info = tls_info(&raw);
                    info.alpn_negotiated = stream.get_ref().1.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned());
                    let ctx = ConnCtx { peer, transport: "https", accepted_at, kernel_rtt_ms: krtt, tls: Some(info) };
                    serve(stream, ctx, st).await;
                });
            }
        } else {
            eprintln!("未提供 --cert/--key，只开 HTTP");
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    })
}
