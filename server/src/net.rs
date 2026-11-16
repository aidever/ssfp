//! socket 层：带 TCP_SAVE_SYN 的监听、按模板拨号、读取 TCP_INFO。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use anyhow::Context as _;
use fpcore::Template;
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::config::Config;

fn setsockopt_int(fd: i32, level: i32, opt: i32, v: i32) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(fd, level, opt, &v as *const _ as *const libc::c_void, std::mem::size_of::<i32>() as u32)
    };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

pub fn listen(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    s.set_reuse_address(true)?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    setsockopt_int(s.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_SAVE_SYN, 1).context("开启 TCP_SAVE_SYN")?;
    s.bind(&addr.into()).with_context(|| format!("绑定 {addr}"))?;
    s.listen(1024)?;
    s.set_nonblocking(true)?;
    Ok(TcpListener::from_std(s.into())?)
}

/// 取回 accept 的连接对应的原始 SYN（IP 头 + TCP 头）。只能取一次。
pub fn saved_syn(s: &TcpStream) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let mut len = buf.len() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_SAVED_SYN, buf.as_mut_ptr() as *mut _, &mut len)
    };
    if r < 0 || len == 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return is_public(IpAddr::V4(m));
            }
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

fn prepare(a: SocketAddr, tpl: &Template, cfg: &Config) -> anyhow::Result<TcpSocket> {
    let s = Socket::new(Domain::for_address(a), Type::STREAM, Some(Protocol::TCP))?;
    if let Some(ttl) = tpl.ttl {
        if a.is_ipv4() { s.set_ttl_v4(ttl)? } else { s.set_unicast_hops_v6(ttl)? }
    }
    if let Some(clamp) = tpl.window_clamp() {
        setsockopt_int(s.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP, clamp as i32).context("设置 TCP_WINDOW_CLAMP")?;
    }
    if cfg.set_mark && tpl.mark != 0 {
        s.set_mark(tpl.mark).context("设置 SO_MARK（需要 CAP_NET_ADMIN）")?;
    }
    let bind: Option<IpAddr> = match a {
        SocketAddr::V4(_) => cfg.egress_v4.map(IpAddr::V4),
        SocketAddr::V6(_) => cfg.egress_v6.map(IpAddr::V6),
    };
    if let Some(ip) = bind {
        s.bind(&SocketAddr::new(ip, 0).into()).with_context(|| format!("绑定出口 {ip}"))?;
    }
    set_keepalive(socket2::SockRef::from(&s), cfg.tcp_keepalive_s).context("设置 keepalive")?;
    s.set_nonblocking(true)?;
    Ok(TcpSocket::from_std_stream(std::net::TcpStream::from(s)))
}

/// TCP keepalive：空闲 secs 秒后开始探测，间隔 secs/3，3 次无响应断开；
/// 同时设 TCP_USER_TIMEOUT，已发数据长时间收不到 ACK（对端消失）时也能断开。secs = 0 时不设置。
pub fn set_keepalive(s: socket2::SockRef<'_>, secs: u64) -> io::Result<()> {
    if secs == 0 {
        return Ok(());
    }
    let t = Duration::from_secs(secs);
    let iv = Duration::from_secs((secs / 3).max(1));
    s.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(t).with_interval(iv).with_retries(3))?;
    s.set_tcp_user_timeout(Some(t + iv * 3))
}

/// Happy Eyeballs（RFC 8305）里两次尝试之间的间隔
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// IPv6 / IPv4 交替排列；首个地址族按解析结果的顺序，prefer_ipv4 时 IPv4 在前
fn interleave(targets: &[SocketAddr], prefer_ipv4: bool) -> Vec<SocketAddr> {
    let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) = targets.iter().partition(|a| a.is_ipv4());
    let v4_first = prefer_ipv4 && !v4.is_empty() || targets.first().is_some_and(|a| a.is_ipv4());
    let (a, b) = if v4_first { (v4, v6) } else { (v6, v4) };
    let mut out = Vec::with_capacity(targets.len());
    let (mut ia, mut ib) = (a.into_iter(), b.into_iter());
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => break,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
    out
}

/// Happy Eyeballs 拨号：按交替顺序每 250ms 发起一个新尝试（上一个失败则立刻发起），
/// 第一个连上的胜出，其余取消；整个过程不超过 timeout。
pub async fn dial(targets: &[SocketAddr], tpl: &Template, cfg: &Config, timeout: Duration) -> anyhow::Result<(TcpStream, SocketAddr)> {
    let order = interleave(targets, cfg.prefer_ipv4);
    match tokio::time::timeout(timeout, race(&order, tpl, cfg)).await {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!("连接超时（{} 秒内 {} 个地址都没连上：{:?}）", timeout.as_secs(), order.len(), order)),
    }
}

async fn race(order: &[SocketAddr], tpl: &Template, cfg: &Config) -> anyhow::Result<(TcpStream, SocketAddr)> {
    let mut set = tokio::task::JoinSet::new();
    let mut next = 0;
    let mut last: Option<anyhow::Error> = None;
    loop {
        // 发起下一个尝试
        if next < order.len() {
            let a = order[next];
            next += 1;
            match prepare(a, tpl, cfg) {
                Ok(sock) => {
                    set.spawn(async move { sock.connect(a).await.map(|s| (s, a)).map_err(|e| (a, e)) });
                }
                Err(e) => {
                    last = Some(e.context(format!("准备连接 {a} 失败")));
                    continue;
                }
            }
        }
        if set.is_empty() {
            return Err(last.unwrap_or_else(|| anyhow::anyhow!("没有可连接的地址")));
        }
        let more = next < order.len();
        tokio::select! {
            r = set.join_next() => match r {
                Some(Ok(Ok(x))) => return Ok(x), // set 被丢弃时其余尝试自动取消
                Some(Ok(Err((a, e)))) => last = Some(anyhow::anyhow!("连接 {a} 失败: {e}")),
                Some(Err(e)) => last = Some(anyhow::anyhow!("连接任务异常: {e}")),
                None => {}
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY), if more => {}
        }
    }
}

struct DnsEntry {
    r: Result<Vec<IpAddr>, String>,
    /// 在此之前直接用缓存
    fresh_until: std::time::Instant,
    /// 在此之前，重新解析失败时仍可用这份旧结果（serve-stale，RFC 8767）
    keep_until: std::time::Instant,
}

/// 带超时和缓存的域名解析（TCP 与 UDP 共用）。
/// 解析器临时故障（超时、EAI_AGAIN）时继续用过期结果，并且不缓存这类失败；
/// 只有"域名不存在 / 没有地址"这类确定的失败缓存 5 秒。
pub struct Resolver {
    cache: std::sync::Mutex<std::collections::HashMap<String, DnsEntry>>,
    timeout: Duration,
    ttl: Duration,
}

const DNS_NEG_TTL: Duration = Duration::from_secs(5);
const DNS_STALE_MAX: Duration = Duration::from_secs(3600);
const DNS_CACHE_MAX: usize = 4096;

fn to_addrs(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect()
}

/// 解析器自身的临时故障（换个时间再试可能成功），区别于域名确实不存在
fn transient(e: &str) -> bool {
    e.contains("Try again") || e.contains("Temporary failure") || e.starts_with("超时")
}

impl Resolver {
    pub fn new(cfg: &Config) -> Self {
        Self {
            cache: Default::default(),
            timeout: Duration::from_secs(cfg.dns_timeout_s),
            ttl: Duration::from_secs(cfg.dns_cache_s),
        }
    }

    /// 只查新鲜的缓存（未命中或已过期返回 None）
    pub fn cached(&self, host: &str, port: u16) -> Option<anyhow::Result<Vec<SocketAddr>>> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let m = self.cache.lock().unwrap();
        let e = m.get(&key).filter(|e| e.fresh_until > std::time::Instant::now())?;
        Some(match &e.r {
            Ok(ips) => Ok(to_addrs(ips, port)),
            Err(e) => Err(anyhow::anyhow!("域名解析失败: {e}")),
        })
    }

    pub async fn resolve(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        if let Some(r) = self.cached(host, port) {
            return r;
        }
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let r: Result<Vec<IpAddr>, String> = match tokio::time::timeout(self.timeout, tokio::net::lookup_host((host, 0))).await {
            Ok(Ok(it)) => {
                let mut v: Vec<IpAddr> = Vec::new();
                for a in it {
                    let ip = a.ip().to_canonical();
                    if !v.contains(&ip) {
                        v.push(ip);
                    }
                }
                if v.is_empty() { Err("没有地址".into()) } else { Ok(v) }
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err(format!("超时（{} 秒）", self.timeout.as_secs())),
        };
        if self.ttl.is_zero() {
            return r.map(|ips| to_addrs(&ips, port)).map_err(|e| anyhow::anyhow!("域名解析失败: {e}"));
        }
        let now = std::time::Instant::now();
        let mut m = self.cache.lock().unwrap();
        match r {
            Ok(ips) => {
                let out = to_addrs(&ips, port);
                if m.len() >= DNS_CACHE_MAX {
                    m.retain(|_, e| e.keep_until > now);
                    if m.len() >= DNS_CACHE_MAX {
                        m.clear();
                    }
                }
                m.insert(key, DnsEntry { r: Ok(ips), fresh_until: now + self.ttl, keep_until: now + DNS_STALE_MAX });
                Ok(out)
            }
            Err(err) => {
                // 解析失败：还留着旧结果就先用旧的
                if let Some(DnsEntry { r: Ok(ips), keep_until, .. }) = m.get(&key)
                    && *keep_until > now
                {
                    return Ok(to_addrs(ips, port));
                }
                if !transient(&err) {
                    m.insert(key, DnsEntry { r: Err(err.clone()), fresh_until: now + DNS_NEG_TTL, keep_until: now + DNS_NEG_TTL });
                }
                Err(anyhow::anyhow!("域名解析失败: {err}"))
            }
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct EgressInfo {
    /// 我方在 SYN 里通告的 wscale（对方未启用窗口缩放时为 null）
    pub our_wscale: Option<u8>,
    pub peer_wscale: Option<u8>,
    pub timestamps: bool,
    pub sack: bool,
    pub ecn: bool,
    pub rtt_ms: f64,
    pub snd_mss: u32,
}

/// 读 TCP_INFO 原始字节，避免 glibc / musl 结构体定义差异。
pub fn egress_info(s: &TcpStream) -> Option<EgressInfo> {
    let mut b = [0u8; 104];
    let mut len = b.len() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    if r < 0 || len < 76 {
        return None;
    }
    let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let opts = b[5];
    let wscale_ok = opts & 4 != 0;
    Some(EgressInfo {
        our_wscale: wscale_ok.then_some(b[6] >> 4),
        peer_wscale: wscale_ok.then_some(b[6] & 0x0f),
        timestamps: opts & 1 != 0,
        sack: opts & 2 != 0,
        ecn: opts & 8 != 0,
        rtt_ms: u32_at(68) as f64 / 1000.0,
        snd_mss: u32_at(16),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaves_families() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let t = [a("[2001::1]:80"), a("[2001::2]:80"), a("1.1.1.1:80"), a("1.0.0.1:80")];
        assert_eq!(interleave(&t, false), vec![t[0], t[2], t[1], t[3]]);
        assert_eq!(interleave(&t, true), vec![t[2], t[0], t[3], t[1]]);
        assert_eq!(interleave(&t[2..], false), vec![t[2], t[3]]);
    }

    #[test]
    fn transient_dns_errors() {
        assert!(transient("failed to lookup address information: Try again"));
        assert!(transient("failed to lookup address information: Temporary failure in name resolution"));
        assert!(transient("超时（5 秒）"));
        assert!(!transient("failed to lookup address information: Name does not resolve"));
    }
}
