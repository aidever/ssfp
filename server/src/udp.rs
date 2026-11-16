//! SS2022 UDP 中继。
//!
//! - 每个 (客户端地址, client_session_id) 一个关联，出站 socket 按模板设置 TTL / hop limit
//! - 模板：设备固定 > 设备学到的 > 同一客户端 IP 最近一次 TCP 判定的结果 > 默认
//! - 设备增删改时用新的用户表重建 ProxySocket（同一个 UDP socket 的 dup）
//! - 默认丢弃目标端口 443 的 UDP（QUIC），让浏览器回落到 TCP，TCP 那边才有 TLS 识别与 SYN 改写
//! - 关联空闲 udp_idle_s 秒后回收，并写一行 JSON 日志

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use fpcore::{Family, Template};
use serde::Serialize;
use shadowsocks::config::ServerUser;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::Address;
use shadowsocks::relay::udprelay::ProxySocket;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::config::TemplateChoice;
use crate::traffic::{ConnBytes, ConnInfo, DevStats};
use crate::{State, now_ms};

type Proxy = Arc<ProxySocket<shadowsocks::net::UdpSocket>>;
type Key = (SocketAddr, u64);

#[derive(Serialize, Default)]
struct AssocLog {
    udp: bool,
    at_unix_ms: u64,
    peer: Option<SocketAddr>,
    user: Option<String>,
    template: Option<Family>,
    template_source: Option<&'static str>,
    /// 首个目标
    first_target: Option<String>,
    pkts_up: u64,
    pkts_down: u64,
    bytes_up: u64,
    bytes_down: u64,
    dropped_quic: u64,
    dropped_other: u64,
    duration_ms: f64,
}

struct Assoc {
    /// 客户端地址可能变化（SS2022 允许），回包发往最新地址
    peer: Mutex<SocketAddr>,
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    server_session_id: u64,
    packet_id: AtomicU64,
    client_session_id: u64,
    user: Option<Arc<ServerUser>>,
    last_seen: Mutex<Instant>,
    log: Mutex<AssocLog>,
    dev_stats: Arc<DevStats>,
    bytes: Arc<ConnBytes>,
    conn_id: u64,
}

impl Assoc {
    fn conn_id(&self) -> u64 {
        self.conn_id
    }

    fn count(&self, up: bool, n: usize) {
        let n = n as u64;
        if up {
            self.dev_stats.up.fetch_add(n, Ordering::Relaxed);
            self.bytes.up.fetch_add(n, Ordering::Relaxed);
        } else {
            self.dev_stats.down.fetch_add(n, Ordering::Relaxed);
            self.bytes.down.fetch_add(n, Ordering::Relaxed);
        }
    }
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    let r = unsafe { libc::getrandom(b.as_mut_ptr() as *mut _, 8, 0) };
    if r != 8 {
        // 不该发生；退化为时间
        return now_ms() ^ 0x9e37_79b9_7f4a_7c15;
    }
    u64::from_ne_bytes(b)
}

fn out_socket(v6: bool, tpl: &Template, st: &State) -> anyhow::Result<UdpSocket> {
    let s = Socket::new(if v6 { Domain::IPV6 } else { Domain::IPV4 }, Type::DGRAM, Some(Protocol::UDP))?;
    if v6 {
        s.set_only_v6(true)?;
    }
    if let Some(ttl) = tpl.ttl {
        if v6 { s.set_unicast_hops_v6(ttl)? } else { s.set_ttl_v4(ttl)? }
    }
    let bind = if v6 {
        SocketAddr::new(st.cfg.egress_v6.map(IpAddr::V6).unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)), 0)
    } else {
        SocketAddr::new(st.cfg.egress_v4.map(IpAddr::V4).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)), 0)
    };
    s.bind(&bind.into()).with_context(|| format!("绑定 UDP 出口 {bind}"))?;
    s.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(s.into())?)
}

impl Assoc {
    /// 从解析结果里挑一个有出口 socket 的地址（prefer_ipv4 时先挑 IPv4）
    fn pick(&self, addrs: &[SocketAddr], prefer_ipv4: bool) -> Option<SocketAddr> {
        let usable = |a: &&SocketAddr| (a.is_ipv4() && self.v4.is_some()) || (a.is_ipv6() && self.v6.is_some());
        if prefer_ipv4 && let Some(a) = addrs.iter().filter(usable).find(|a| a.is_ipv4()) {
            return Some(*a);
        }
        addrs.iter().find(usable).copied()
    }

    fn ctrl(&self) -> UdpSocketControlData {
        let mut c = UdpSocketControlData::default();
        c.client_session_id = self.client_session_id;
        c.server_session_id = self.server_session_id;
        c.packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed) + 1;
        c.user = self.user.clone();
        c
    }
}

/// 出站 socket 收到的回包转给客户端；空闲超时后退出
async fn downlink(a: Arc<Assoc>, sock: Arc<UdpSocket>, proxy: Proxy, idle: Duration) {
    let mut buf = vec![0u8; 65536];
    loop {
        let r = tokio::time::timeout(idle, sock.recv_from(&mut buf)).await;
        let (n, from) = match r {
            Ok(Ok(x)) => x,
            Ok(Err(_)) => {
                // 一般不会持续出错；万一出错别空转
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            Err(_) => {
                if a.last_seen.lock().unwrap().elapsed() >= idle {
                    return;
                }
                continue;
            }
        };
        *a.last_seen.lock().unwrap() = Instant::now();
        let peer = *a.peer.lock().unwrap();
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        if proxy.send_to_with_ctrl(peer, &Address::SocketAddress(from), &a.ctrl(), &buf[..n]).await.is_ok() {
            a.count(false, n);
            let mut l = a.log.lock().unwrap();
            l.pkts_down += 1;
            l.bytes_down += n as u64;
        }
    }
}

/// 用当前用户表包一层 ProxySocket（底层是同一个 UDP socket 的 dup）
fn build_proxy(st: &State, ctx: &SharedContext, sock: &std::net::UdpSocket) -> anyhow::Result<Proxy> {
    let mut svr = st.svr.clone();
    if let Some(um) = &st.store.snapshot().users {
        svr.set_user_manager((**um).clone());
    }
    let s = UdpSocket::from_std(sock.try_clone()?)?;
    Ok(Arc::new(ProxySocket::from_socket(
        shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Server,
        ctx.clone(),
        &svr,
        shadowsocks::net::UdpSocket::from(s),
    )))
}

pub async fn serve(st: Arc<State>, ctx: SharedContext) -> anyhow::Result<()> {
    let sock = std::net::UdpSocket::bind(st.cfg.listen).with_context(|| format!("UDP 绑定 {}", st.cfg.listen))?;
    sock.set_nonblocking(true)?;
    let mut changes = st.store.subscribe();
    let mut proxy = build_proxy(&st, &ctx, &sock)?;
    let assocs: Arc<Mutex<HashMap<Key, Arc<Assoc>>>> = Arc::default();
    let idle = Duration::from_secs(st.cfg.udp_idle_s.max(10));
    let mut buf = vec![0u8; 65536];
    loop {
        let r = tokio::select! {
            r = proxy.recv_from_with_ctrl(&mut buf) => r,
            _ = changes.changed() => {
                match build_proxy(&st, &ctx, &sock) {
                    Ok(p) => proxy = p,
                    Err(e) => eprintln!("UDP 用户表更新失败: {e:#}"),
                }
                continue;
            }
        };
        let (n, peer, target, _, ctrl) = match r {
            Ok(x) => x,
            Err(_) => continue, // 解密失败、重放等：静默丢弃
        };
        let Some(ctrl) = ctrl else { continue };
        // 设备已停用 / 删除：丢弃（已有关联会在空闲后回收）
        if let Some(u) = &ctrl.user {
            if !st.store.snapshot().by_key.contains_key(u.key()) {
                continue;
            }
        }
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let key = (peer, ctrl.client_session_id);
        // 同一会话换了源地址：按 session id 找回
        let existing = {
            let m = assocs.lock().unwrap();
            m.get(&key).cloned().or_else(|| {
                m.iter().find(|((_, id), a)| *id == ctrl.client_session_id && a.user_key() == ctrl.user.as_ref().map(|u| u.key().to_vec())).map(|(_, a)| a.clone())
            })
        };
        let a = match existing {
            Some(a) => a,
            None => match new_assoc(&st, peer, &ctrl, &proxy, &assocs, idle) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("UDP 关联创建失败: {e:#}");
                    continue;
                }
            },
        };
        *a.peer.lock().unwrap() = peer;
        *a.last_seen.lock().unwrap() = Instant::now();

        // QUIC 按端口直接丢，不必解析
        if st.cfg.block_quic && target.port() == 443 {
            a.log.lock().unwrap().dropped_quic += 1;
            continue;
        }
        // IP 目标或缓存命中：就地发送；否则交给单独的任务解析，主循环不等 DNS
        let resolved = match &target {
            Address::SocketAddress(x) => Some(Ok(vec![*x])),
            Address::DomainNameAddress(h, p) => st.dns.cached(h, *p),
        };
        match resolved {
            Some(r) => forward(&st, &a, r.ok(), &target, &buf[..n]).await,
            None => {
                let (st, a, data) = (st.clone(), a.clone(), buf[..n].to_vec());
                tokio::spawn(async move {
                    let r = match &target {
                        Address::DomainNameAddress(h, p) => st.dns.resolve(h, *p).await.ok(),
                        Address::SocketAddress(x) => Some(vec![*x]),
                    };
                    forward(&st, &a, r, &target, &data).await;
                });
            }
        }
    }
}

/// 解析后的上行转发：检查目标、选出口、发送、计数
async fn forward(st: &State, a: &Assoc, addrs: Option<Vec<SocketAddr>>, target: &Address, data: &[u8]) {
    let Some(dst) = addrs.and_then(|v| a.pick(&v, st.cfg.prefer_ipv4)) else {
        a.log.lock().unwrap().dropped_other += 1;
        return;
    };
    let dev = a.user.as_ref().and_then(|u| st.store.snapshot().by_key.get(u.key()).cloned());
    if !st.target_allowed(&dst, dev.as_ref()) {
        a.log.lock().unwrap().dropped_other += 1;
        return;
    }
    let out = if dst.is_ipv4() { a.v4.as_ref() } else { a.v6.as_ref() };
    let Some(out) = out else {
        a.log.lock().unwrap().dropped_other += 1;
        return;
    };
    if out.send_to(data, dst).await.is_ok() {
        a.count(true, data.len());
        let mut l = a.log.lock().unwrap();
        if l.first_target.is_none() {
            l.first_target = Some(target.to_string());
            st.traffic.update_conn(a.conn_id(), |c| c.target = format!("UDP {target}"));
        }
        l.pkts_up += 1;
        l.bytes_up += data.len() as u64;
    }
}

impl Assoc {
    fn user_key(&self) -> Option<Vec<u8>> {
        self.user.as_ref().map(|u| u.key().to_vec())
    }
}

fn new_assoc(
    st: &Arc<State>,
    peer: SocketAddr,
    ctrl: &UdpSocketControlData,
    proxy: &Proxy,
    assocs: &Arc<Mutex<HashMap<Key, Arc<Assoc>>>>,
    idle: Duration,
) -> anyhow::Result<Arc<Assoc>> {
    let info = ctrl.user.as_ref().and_then(|u| st.store.snapshot().by_key.get(u.key()).cloned());
    let (family, source) = match info.as_ref().map(|d| (d.template, d.learned)) {
        Some((TemplateChoice::Fixed(f), _)) => (f, "user"),
        Some((TemplateChoice::Auto, Some(f))) => (f, "learned"),
        _ => match st.recent_family(peer.ip()) {
            Some(f) => (f, "recent_tcp"),
            None => match st.cfg.default_template {
                TemplateChoice::Fixed(f) => (f, "default"),
                TemplateChoice::Auto => (Family::None, "default"),
            },
        },
    };
    let tpl = Template::of(family);
    let v4 = out_socket(false, &tpl, st).ok().map(Arc::new);
    let v6 = out_socket(true, &tpl, st).ok().map(Arc::new);
    anyhow::ensure!(v4.is_some() || v6.is_some(), "没有可用的 UDP 出口");
    let dev_id = info.as_ref().map(|d| d.id).unwrap_or(0);
    let (conn_id, bytes) = st.traffic.open_conn(ConnInfo {
        id: 0,
        device_id: dev_id,
        device: info.as_ref().map(|d| d.label()).unwrap_or_else(|| "（单用户 PSK）".into()),
        target: "UDP".into(),
        template: Some(TemplateChoice::Fixed(family).name()),
        template_source: Some(source.into()),
        udp: true,
        started_ms: now_ms(),
        abort: None,
        stats: None,
    });
    let a = Arc::new(Assoc {
        dev_stats: st.traffic.dev(dev_id),
        bytes,
        conn_id,
        peer: Mutex::new(peer),
        v4,
        v6,
        server_session_id: rand_u64(),
        packet_id: AtomicU64::new(0),
        client_session_id: ctrl.client_session_id,
        user: ctrl.user.clone(),
        last_seen: Mutex::new(Instant::now()),
        log: Mutex::new(AssocLog {
            udp: true,
            at_unix_ms: now_ms(),
            peer: Some(peer),
            user: info.as_ref().map(|d| d.label()),
            template: Some(family),
            template_source: Some(source),
            ..Default::default()
        }),
    });
    assocs.lock().unwrap().insert((peer, ctrl.client_session_id), a.clone());

    let (st, proxy, assocs, a2) = (st.clone(), proxy.clone(), assocs.clone(), a.clone());
    let t0 = Instant::now();
    tokio::spawn(async move {
        let mut tasks = Vec::new();
        for s in [a2.v4.clone(), a2.v6.clone()].into_iter().flatten() {
            tasks.push(tokio::spawn(downlink(a2.clone(), s, proxy.clone(), idle)));
        }
        for t in tasks {
            let _ = t.await;
        }
        assocs.lock().unwrap().retain(|_, v| !Arc::ptr_eq(v, &a2));
        st.traffic.close_conn(conn_id);
        let mut l = std::mem::take(&mut *a2.log.lock().unwrap());
        l.duration_ms = t0.elapsed().as_secs_f64() * 1e3;
        if let Ok(v) = serde_json::to_value(&l) {
            st.write_value(&v);
        }
    });
    Ok(a)
}
