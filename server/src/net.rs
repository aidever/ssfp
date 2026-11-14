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
    s.set_nonblocking(true)?;
    Ok(TcpSocket::from_std_stream(std::net::TcpStream::from(s)))
}

/// 依次尝试解析出的地址，返回第一个连上的。
pub async fn dial(targets: &[SocketAddr], tpl: &Template, cfg: &Config, timeout: Duration) -> anyhow::Result<(TcpStream, SocketAddr)> {
    let mut last = None;
    for &a in targets {
        let sock = prepare(a, tpl, cfg)?;
        match tokio::time::timeout(timeout, sock.connect(a)).await {
            Ok(Ok(s)) => return Ok((s, a)),
            Ok(Err(e)) => last = Some(anyhow::anyhow!("连接 {a} 失败: {e}")),
            Err(_) => last = Some(anyhow::anyhow!("连接 {a} 超时")),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("没有可连接的地址")))
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
