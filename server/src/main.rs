//! ssfp：Shadowsocks 2022 服务端，出口 TCP 指纹按设备的系统模板设置。
//!
//! - 用户 / 设备在看板或 `ssfp ctl` 里管理，每台设备一把密钥，密钥 → 设备 → 模板，改动立即生效
//! - 监听 socket 开 TCP_SAVE_SYN，accept 后立刻取回客户端 SYN
//! - SS2022 握手拿到目标地址，再读首包（随请求头一起到达，或最多等 first_data_wait_ms）
//! - 按模板设置出站 socket（TTL、TCP_WINDOW_CLAMP 控 wscale、SO_MARK → eBPF 改写 SYN），bind 出口 IP
//! - connect 成功后立刻写首包；按设备统计流量；每条连接写一行 JSON 日志

mod admin;
mod classify;
mod config;
mod console;
mod ctl;
mod ebpf;
mod net;
mod store;
mod traffic;
mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use fpcore::{Family, SynFields, Template};
use serde::Serialize;
use shadowsocks::config::ServerConfig;
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::Address;
use shadowsocks::relay::tcprelay::ProxyServerStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use config::{Config, TemplateChoice};
use store::{DevInfo, Store};
use traffic::{ConnInfo, Counted, Traffic};

const FIRST_DATA_MAX: usize = 16 * 1024;
const RECENT_TTL: Duration = Duration::from_secs(600);

pub struct State {
    cfg: Config,
    method: CipherKind,
    svr: ServerConfig,
    store: Arc<Store>,
    traffic: Arc<Traffic>,
    /// 连接日志：交给后台线程写，转发线程不碰磁盘
    log: Option<std::sync::mpsc::SyncSender<String>>,
    dns: net::Resolver,
    /// 客户端 IP → 最近一次 TCP 自动判定的模板，UDP 关联沿用
    recent: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (Family, Instant)>>,
    admin_token: String,
    public_host: String,
    ebpf_iface: std::sync::Mutex<Option<String>>,
    ebpf_error: std::sync::Mutex<Option<String>>,
    ebpf: std::sync::Mutex<Option<ebpf::SynRewriter>>,
}

#[derive(Serialize, Default)]
struct ConnLog {
    at_unix_ms: u64,
    peer: Option<SocketAddr>,
    user: Option<String>,
    target: Option<String>,
    resolved: Option<SocketAddr>,
    client_syn: Option<SynFields>,
    /// 选中的模板与来源（user / learned / ua / ja4 / syn / default）
    template: Option<Family>,
    template_source: Option<classify::Source>,
    signals: Option<classify::Signals>,
    first_data_len: usize,
    /// 等首包花的时间
    first_data_wait_ms: f64,
    connect_ms: Option<f64>,
    /// 出站连接实际协商结果（TCP_INFO），用于核对模板是否生效
    egress: Option<net::EgressInfo>,
    bytes_up: u64,
    bytes_down: u64,
    duration_ms: f64,
    error: Option<String>,
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

impl State {
    fn remember_family(&self, ip: std::net::IpAddr, f: Family) {
        let mut m = self.recent.lock().unwrap();
        if m.len() > 4096 {
            m.retain(|_, (_, t)| t.elapsed() < RECENT_TTL);
        }
        m.insert(ip, (f, Instant::now()));
    }

    fn recent_family(&self, ip: std::net::IpAddr) -> Option<Family> {
        self.recent.lock().unwrap().get(&ip).filter(|(_, t)| t.elapsed() < RECENT_TTL).map(|(f, _)| *f)
    }

    fn write(&self, l: &ConnLog) {
        if let Ok(v) = serde_json::to_value(l) {
            self.write_value(&v);
        }
    }

    fn write_value(&self, v: &serde_json::Value) {
        let line = v.to_string();
        match &self.log {
            // 队列满（磁盘卡住）时丢弃这一行，不阻塞转发
            Some(tx) => {
                let _ = tx.try_send(line);
            }
            None => eprintln!("{line}"),
        }
    }

    /// eBPF 写包失败会丢掉 SYN（内核 1s / 3s 后重传，连接很慢甚至超时）。
    /// 一分钟内持续失败且多于成功时摘掉程序，退回只改 TTL / wscale，保证连得上。
    fn check_ebpf_health(&self, d: &serde_json::Value) {
        let n = |k: &str| d[k].as_u64().unwrap_or(0);
        let (fail, ok) = (n("store_fail"), n("rewritten"));
        if fail < 3 || fail <= ok {
            return;
        }
        let msg = format!("一分钟内 SYN 改写失败 {fail} 次、成功 {ok} 次，已自动停用 eBPF 改写（只改 TTL / wscale）");
        eprintln!("警告：{msg}");
        *self.ebpf.lock().unwrap() = None; // 丢弃即从网卡摘除
        *self.ebpf_iface.lock().unwrap() = None;
        *self.ebpf_error.lock().unwrap() = Some(msg.clone());
        self.write_value(&serde_json::json!({ "at_unix_ms": now_ms(), "warning": msg }));
    }

    /// block_private 时仍放行：设备的 private_allow，以及看板 / 订阅地址
    fn target_allowed(&self, a: &SocketAddr, dev: Option<&DevInfo>) -> bool {
        !self.cfg.block_private
            || net::is_public(a.ip())
            || dev.is_some_and(|d| d.private_allow.contains(a))
            || self.cfg.console_listen.is_some_and(|c| c == *a)
    }

    /// 设备模板：固定 > 学到的 > 自动判定（UA / JA4 / SYN）> 默认
    fn decide(&self, dev: Option<&DevInfo>, sig: &classify::Signals, syn: Option<&SynFields>) -> (Family, classify::Source) {
        match dev.map(|d| (d.template, d.learned)) {
            Some((TemplateChoice::Fixed(f), _)) => (f, classify::Source::User),
            Some((TemplateChoice::Auto, Some(f))) => (f, classify::Source::Learned),
            _ => classify::decide(None, self.cfg.default_template, sig, syn, &self.cfg.ja4),
        }
    }
}

/// 连接结束（包括被看板断开）时从在线列表移除
struct ConnGuard {
    traffic: Arc<Traffic>,
    id: Option<u64>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.traffic.close_conn(id);
        }
    }
}

async fn handle(
    mut stream: ProxyServerStream<TcpStream>,
    peer: SocketAddr,
    st: Arc<State>,
    abort: tokio::sync::oneshot::Receiver<tokio::task::AbortHandle>,
) {
    let t0 = Instant::now();
    let mut log = ConnLog { at_unix_ms: now_ms(), peer: Some(peer), ..Default::default() };
    let mut guard = ConnGuard { traffic: st.traffic.clone(), id: None };
    if let Err(e) = relay(&mut stream, &st, &mut log, &mut guard, abort).await {
        log.error = Some(format!("{e:#}"));
    }
    log.duration_ms = t0.elapsed().as_secs_f64() * 1e3;
    st.write(&log);
}

async fn relay(
    stream: &mut ProxyServerStream<TcpStream>,
    st: &State,
    log: &mut ConnLog,
    guard: &mut ConnGuard,
    abort: tokio::sync::oneshot::Receiver<tokio::task::AbortHandle>,
) -> anyhow::Result<()> {
    // 1. 客户端 SYN：只能读一次，必须在握手前取
    log.client_syn = net::saved_syn(stream.get_ref()).and_then(|b| fpcore::parse_syn(&b));

    // 2. SS 握手；按密钥找到设备
    let addr = tokio::time::timeout(Duration::from_secs(30), stream.handshake())
        .await
        .context("握手超时")?
        .context("握手失败")?;
    let snap = st.store.snapshot();
    let dev = stream.user_key().and_then(|k| snap.by_key.get(k)).cloned();
    log.user = dev.as_ref().map(|d| d.label());
    log.target = Some(addr.to_string());

    // 自动模板的设备：从系统服务域名学习
    if let (Some(d), Address::DomainNameAddress(h, _)) = (&dev, &addr) {
        if matches!(d.template, TemplateChoice::Auto) {
            if let Some(f) = store::hint_family(h) {
                st.store.learn(d.id, f, h);
            }
        }
    }

    // 3. 首包：SS2022 通常随请求头一起到达，否则最多等 first_data_wait_ms
    let tw = Instant::now();
    let mut first = vec![0u8; FIRST_DATA_MAX];
    let n = match tokio::time::timeout(Duration::from_millis(st.cfg.first_data_wait_ms), stream.read(&mut first)).await {
        Ok(Ok(0)) => anyhow::bail!("客户端在发送数据前关闭"),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e).context("读取首包失败"),
        Err(_) => 0,
    };
    first.truncate(n);
    log.first_data_len = n;
    log.first_data_wait_ms = tw.elapsed().as_secs_f64() * 1e3;

    // 4. 选模板
    let sig = classify::signals(&first);
    let (family, source) = st.decide(dev.as_ref(), &sig, log.client_syn.as_ref());
    log.template = Some(family);
    log.template_source = Some(source);
    if matches!(source, classify::Source::Ua | classify::Source::Ja4 | classify::Source::Syn) {
        if let Some(p) = log.peer {
            st.remember_family(p.ip().to_canonical(), family);
        }
    }
    log.signals = Some(sig);
    let tpl = Template::of(family);

    // 5. 登记在线连接（看板可断开）
    let dev_id = dev.as_ref().map(|d| d.id).unwrap_or(0);
    let (cid, bytes) = st.traffic.open_conn(ConnInfo {
        id: 0,
        device_id: dev_id,
        device: dev.as_ref().map(|d| d.label()).unwrap_or_else(|| "（单用户 PSK）".into()),
        target: addr.to_string(),
        template: Some(TemplateChoice::Fixed(family).name()),
        template_source: serde_json::to_value(source).ok().and_then(|v| v.as_str().map(String::from)),
        udp: false,
        started_ms: now_ms(),
        abort: None,
        stats: None,
    });
    guard.id = Some(cid);
    if let Ok(h) = abort.await {
        st.traffic.set_abort(cid, h);
    }

    // 6. 解析目标，拒绝内网地址
    let targets: Vec<SocketAddr> = match &addr {
        Address::SocketAddress(a) => vec![*a],
        Address::DomainNameAddress(h, p) => st.dns.resolve(h, *p).await?,
    };
    let targets: Vec<SocketAddr> = targets.into_iter().filter(|a| st.target_allowed(a, dev.as_ref())).collect();
    anyhow::ensure!(!targets.is_empty(), "目标没有可用的公网地址");

    // 7. 按模板拨号，连上立刻写首包
    let tc = Instant::now();
    let (out, resolved) = net::dial(&targets, &tpl, &st.cfg, Duration::from_secs(st.cfg.connect_timeout_s)).await?;
    log.connect_ms = Some(tc.elapsed().as_secs_f64() * 1e3);
    log.resolved = Some(resolved);
    log.egress = net::egress_info(&out);
    let mut out = Counted::new(out, st.traffic.dev(dev_id), bytes.clone());
    if !first.is_empty() {
        out.write_all(&first).await.context("写首包失败")?;
    }

    // 8. 双向转发；双向都没有数据超过 tcp_idle_s 时关闭（keepalive 只能发现对端消失，发现不了"活着但不再用"）
    let r = relay_with_idle(stream, &mut out, &bytes, st.cfg.tcp_idle_s).await;
    log.bytes_up = bytes.up.load(Relaxed);
    log.bytes_down = bytes.down.load(Relaxed);
    if let Err(e) = r {
        log.error = Some(format!("转发中断: {e}"));
    }
    Ok(())
}

async fn relay_with_idle(
    a: &mut ProxyServerStream<TcpStream>,
    b: &mut Counted<TcpStream>,
    bytes: &traffic::ConnBytes,
    idle_s: u64,
) -> std::io::Result<(u64, u64)> {
    let copy = tokio::io::copy_bidirectional_with_sizes(a, b, RELAY_BUF, RELAY_BUF);
    if idle_s == 0 {
        return copy.await;
    }
    tokio::pin!(copy);
    let idle = Duration::from_secs(idle_s);
    let mut iv = tokio::time::interval(Duration::from_secs(idle_s.clamp(1, 30)));
    let mut last = (0, 0);
    let mut quiet_since = Instant::now();
    loop {
        tokio::select! {
            r = &mut copy => return r,
            _ = iv.tick() => {
                let now = (bytes.up.load(Relaxed), bytes.down.load(Relaxed));
                if now != last {
                    last = now;
                    quiet_since = Instant::now();
                } else if quiet_since.elapsed() >= idle {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("空闲 {idle_s} 秒，已关闭")));
                }
            }
        }
    }
}

/// 转发缓冲（每个方向）
const RELAY_BUF: usize = 32 * 1024;

fn default_public_host() -> String {
    // 取默认路由出口的 IPv4（不发包）
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:53")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

pub fn admin_token(dir: &std::path::Path) -> anyhow::Result<String> {
    let p = dir.join("admin.token");
    if let Ok(t) = std::fs::read_to_string(&p) {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    std::fs::create_dir_all(dir)?;
    let t = store::random_token() + &store::random_token();
    std::fs::write(&p, &t)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    Ok(t)
}

/// 连接日志轮转阈值
const LOG_MAX: u64 = 64 << 20;

/// 后台写日志线程：超过 LOG_MAX 时轮转为 .1（只保留一份旧文件）
fn spawn_log_writer(path: String) -> anyhow::Result<std::sync::mpsc::SyncSender<String>> {
    use std::io::Write;
    let open = |p: &str| std::fs::OpenOptions::new().create(true).append(true).open(p);
    let mut f = std::io::BufWriter::new(open(&path).with_context(|| format!("打开日志 {path}"))?);
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(8192);
    std::thread::Builder::new().name("ssfp-log".into()).spawn(move || {
        while let Ok(line) = rx.recv() {
            let _ = writeln!(f, "{line}");
            // 把已排队的行一起写完再 flush
            while let Ok(l) = rx.try_recv() {
                let _ = writeln!(f, "{l}");
            }
            let _ = f.flush();
            if f.get_ref().metadata().map(|m| m.len() > LOG_MAX).unwrap_or(false) {
                let _ = std::fs::rename(&path, format!("{path}.1"));
                if let Ok(nf) = open(&path) {
                    f = std::io::BufWriter::new(nf);
                }
            }
        }
    })?;
    Ok(tx)
}

const MAIN_HELP: &str = "ssfp —— 出口 TCP 指纹跟随设备系统的 Shadowsocks 2022 服务端
用法：
  ssfp [配置路径]        运行服务（默认 /etc/ssfp/config.toml）
  ssfp init [...]        生成配置（ssfp init --help）
  ssfp check [-c 配置]   体检：配置、内核参数、服务与 eBPF 状态
  ssfp ctl ...           管理用户 / 设备 / 订阅（ssfp ctl help）
  ssfp version";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match args.get(1).map(String::as_str) {
        Some("ctl") => return rt.block_on(ctl::run(&args[2..])),
        Some("init") => return admin::run_init(&args[2..]),
        Some("check") => return rt.block_on(admin::run_check(&args[2..])),
        Some("version" | "--version" | "-V") => {
            println!("ssfp {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("help" | "--help" | "-h") => {
            println!("{MAIN_HELP}");
            return Ok(());
        }
        _ => {}
    }
    rt.block_on(serve(args.get(1).cloned().unwrap_or_else(|| admin::DEFAULT_CONFIG.into())))
}

async fn serve(path: String) -> anyhow::Result<()> {
    let cfg = Config::load(&path)?;
    let method: CipherKind = cfg.method.parse().map_err(|_| anyhow::anyhow!("不支持的加密方式 {}", cfg.method))?;
    anyhow::ensure!(method.is_aead_2022(), "只支持 SS2022 加密方式");
    let svr = ServerConfig::new(cfg.listen, cfg.password.clone(), method).map_err(|e| anyhow::anyhow!("服务端密钥无效: {e}"))?;

    let dir = std::path::PathBuf::from(&cfg.state_dir);
    let store = Store::open(&dir, method.key_len(), &cfg.users)?;
    let traffic = Traffic::open(&dir);
    let admin_token = admin_token(&dir)?;

    let log = match &cfg.log {
        Some(p) => Some(spawn_log_writer(p.clone())?),
        None => None,
    };

    let listener = net::listen(cfg.listen)?;
    let context: SharedContext = Context::new_shared(shadowsocks::config::ServerType::Server);
    let devices = store.with(|d| d.devices.len());
    eprintln!(
        "ssfp 监听 {}（TCP{}），{}，{} 台设备，默认模板 {:?}",
        cfg.listen,
        if cfg.udp { if cfg.block_quic { " + UDP，丢弃 UDP 443" } else { " + UDP" } } else { "" },
        cfg.method,
        devices,
        cfg.default_template
    );
    // eBPF 挂不上（容器 / OpenVZ / 老内核）时继续运行：TTL、wscale 仍按模板，只是 SYN 选项布局和窗口不改
    let mut ebpf_error = None;
    let rewriter = match &cfg.syn_rewrite_iface {
        Some(iface) => match ebpf::SynRewriter::attach(iface, cfg.syn_rewrite_l3_offset) {
            Ok(r) => {
                eprintln!("eBPF SYN 改写已挂到 {iface} egress（L3 偏移 {}）", cfg.syn_rewrite_l3_offset);
                Some(r)
            }
            Err(e) => {
                eprintln!("警告：eBPF SYN 改写没有挂上，只改 TTL / wscale：{e:#}");
                ebpf_error = Some(format!("{e:#}"));
                None
            }
        },
        None => {
            eprintln!("未启用 eBPF SYN 改写（syn_rewrite_iface = off 或找不到默认路由网卡）");
            None
        }
    };
    let public_host = cfg.public_host.clone().unwrap_or_else(default_public_host);
    let st = Arc::new(State {
        ebpf_iface: std::sync::Mutex::new(rewriter.as_ref().and(cfg.syn_rewrite_iface.clone())),
        ebpf_error: std::sync::Mutex::new(ebpf_error),
        ebpf: std::sync::Mutex::new(rewriter),
        dns: net::Resolver::new(&cfg),
        cfg,
        method,
        svr: svr.clone(),
        store,
        traffic,
        log,
        recent: Default::default(),
        admin_token,
        public_host,
    });

    if st.cfg.udp {
        let (st2, ctx2) = (st.clone(), context.clone());
        tokio::spawn(async move {
            if let Err(e) = udp::serve(st2, ctx2).await {
                eprintln!("UDP 中继退出: {e:#}");
            }
        });
    }
    if let Some(addr) = st.cfg.console_listen {
        let st2 = st.clone();
        tokio::spawn(async move {
            if let Err(e) = console::serve(st2, addr).await {
                eprintln!("看板退出: {e:#}");
            }
        });
    }

    // 定时：5 秒采样速率；60 秒记账落盘、写 eBPF 计数
    {
        let st2 = st.clone();
        tokio::spawn(async move {
            let mut tick = 0u64;
            let mut iv = tokio::time::interval(Duration::from_secs(5));
            loop {
                iv.tick().await;
                tick += 1;
                st2.traffic.sample();
                if tick % 12 == 0 {
                    // 落盘放到阻塞线程池，不占转发线程
                    let st3 = st2.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        st3.traffic.roll();
                        st3.store.flush();
                    })
                    .await;
                    let delta = st2.ebpf.lock().unwrap().as_mut().and_then(|r| r.stats_delta());
                    if let Some(v) = delta {
                        st2.write_value(&v);
                        st2.check_ebpf_health(&v["ebpf_stats"]);
                    }
                }
            }
        });
    }

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((tcp, peer)) => {
                    let _ = tcp.set_nodelay(true);
                    let _ = net::set_keepalive(socket2::SockRef::from(&tcp), st.cfg.tcp_keepalive_s);
                    let snap = st.store.snapshot();
                    let stream = ProxyServerStream::from_stream_with_user_manager(
                        context.clone(), tcp, st.method, st.svr.key(), snap.users.clone());
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let h = tokio::spawn(handle(stream, peer, st.clone(), rx));
                    let _ = tx.send(h.abort_handle());
                }
                Err(e) => {
                    eprintln!("accept 失败: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            _ = term.recv() => {
                st.traffic.roll();
                st.store.flush();
                eprintln!("收到 SIGTERM，已保存流量数据");
                return Ok(());
            }
        }
    }
}
