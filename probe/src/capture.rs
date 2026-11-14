//! 被动抓包：AF_PACKET + cBPF，只收靶机端口上的 TCP 包。
//! 记录每个客户端连接的 SYN 原始字段、huginn(p0f) 匹配结果，以及握手各阶段的内核时间戳。

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use huginn_net_db::{SharedTcpSignatureMatcher, TcpDatabase};
use huginn_net_tcp::{ConnectionTracker, MatchQuality, MatchRank};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use serde::Serialize;

pub type FlowTable = Arc<Mutex<HashMap<SocketAddr, Flow>>>;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SynFields {
    pub ip_version: u8,
    pub ttl: u8,
    /// 由观测 TTL 推断的初始 TTL（64 / 128 / 255）
    pub initial_ttl: u16,
    pub hops: u16,
    pub df: bool,
    pub ip_id: u32,
    pub tos: u8,
    /// IP 头 ECN 位（ECT/CE）
    pub ip_ecn: u8,
    pub ip_total_len: u16,
    /// TCP 头里的 ECE / CWR 标志（ECN 协商）
    pub ece: bool,
    pub cwr: bool,
    pub window: u16,
    pub data_offset: u8,
    /// 按出现顺序排列的选项，如 ["MSS=1460","NOP","WS=8","NOP","NOP","SACK_PERM"]
    pub options: Vec<String>,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_perm: bool,
    pub timestamps: bool,
    pub tsval: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct P0fMatch {
    pub os: Option<String>,
    pub os_kind: Option<String>,
    pub quality: String,
    pub score: f32,
    pub dist: u8,
    pub signature: String,
    pub mtu: Option<u16>,
    pub link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AckFields {
    pub window: u16,
    pub timestamps: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Flow {
    /// 所有时间戳均为内核收发时间，Unix 纳秒
    pub syn_at: Option<u64>,
    pub syn_retrans_at: Vec<u64>,
    pub synack_at: Option<u64>,
    pub ack_at: Option<u64>,
    pub first_data_at: Option<u64>,
    pub first_data_len: Option<usize>,
    pub syn: Option<SynFields>,
    pub p0f: Option<P0fMatch>,
    pub ack: Option<AckFields>,
    #[serde(skip)]
    last_seen: u64,
}

impl Flow {
    pub fn handshake_rtt_ms(&self) -> Option<f64> {
        Some((self.ack_at?.checked_sub(self.synack_at?)?) as f64 / 1e6)
    }
    pub fn ack_to_data_ms(&self) -> Option<f64> {
        Some((self.first_data_at?.checked_sub(self.ack_at?)?) as f64 / 1e6)
    }
}

pub fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

/// tcpdump -y RAW -dd 'tcp and (port 8443 or port 8080)'，端口在运行时替换。
const FILTER_TEMPLATE: [(u16, u8, u8, u32); 26] = [
    (0x30, 0, 0, 0x00000000),
    (0x54, 0, 0, 0x000000f0),
    (0x15, 0, 10, 0x00000040),
    (0x30, 0, 0, 0x00000009),
    (0x15, 0, 20, 0x00000006),
    (0x28, 0, 0, 0x00000006),
    (0x45, 18, 0, 0x00001fff),
    (0xb1, 0, 0, 0x00000000),
    (0x48, 0, 0, 0x00000000),
    (0x15, 14, 0, 0x000020fb),
    (0x15, 13, 0, 0x00001f90),
    (0x48, 0, 0, 0x00000002),
    (0x15, 11, 10, 0x000020fb),
    (0x30, 0, 0, 0x00000000),
    (0x54, 0, 0, 0x000000f0),
    (0x15, 0, 9, 0x00000060),
    (0x30, 0, 0, 0x00000006),
    (0x15, 0, 7, 0x00000006),
    (0x28, 0, 0, 0x00000028),
    (0x15, 4, 0, 0x000020fb),
    (0x15, 3, 0, 0x00001f90),
    (0x28, 0, 0, 0x0000002a),
    (0x15, 1, 0, 0x000020fb),
    (0x15, 0, 1, 0x00001f90),
    (0x6, 0, 0, 0x00040000),
    (0x6, 0, 0, 0x00000000),
];

pub struct Capture {
    fd: libc::c_int,
    ports: Vec<u16>,
    table: FlowTable,
    tracker: ConnectionTracker,
    matcher: SharedTcpSignatureMatcher,
}

impl Capture {
    pub fn open(iface: &str, tls_port: u16, http_port: u16, table: FlowTable) -> anyhow::Result<Self> {
        let db = TcpDatabase::load_default().map_err(|e| anyhow::anyhow!("加载 p0f 数据库失败: {e}"))?;
        let matcher = SharedTcpSignatureMatcher::new(Arc::new(db));
        unsafe {
            let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto);
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            // 先挂过滤器再 bind，避免过滤器生效前进来无关包
            let mut insns: Vec<libc::sock_filter> = FILTER_TEMPLATE
                .iter()
                .map(|&(code, jt, jf, k)| {
                    let k = match (code, k) {
                        (0x15, 0x20fb) => tls_port as u32,
                        (0x15, 0x1f90) => http_port as u32,
                        _ => k,
                    };
                    libc::sock_filter { code, jt, jf, k }
                })
                .collect();
            let prog = libc::sock_fprog { len: insns.len() as u16, filter: insns.as_mut_ptr() };
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                &one as *const _ as *const libc::c_void,
                4,
            );
            let name = CString::new(iface)?;
            let ifindex = libc::if_nametoindex(name.as_ptr());
            if ifindex == 0 {
                return Err(anyhow::anyhow!("找不到网卡 {iface}"));
            }
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            sll.sll_ifindex = ifindex as i32;
            if libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self {
                fd,
                ports: vec![tls_port, http_port],
                table,
                tracker: ConnectionTracker::new(1000),
                matcher,
            })
        }
    }

    pub fn run(mut self) {
        let mut buf = vec![0u8; 65536];
        let mut last_prune = now_ns();
        loop {
            match self.recv(&mut buf) {
                Ok((n, ts, outgoing)) => self.handle(&buf[..n], ts, outgoing),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("抓包错误: {e}");
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            let now = now_ns();
            if now - last_prune > 30_000_000_000 {
                last_prune = now;
                let cutoff = now.saturating_sub(600_000_000_000);
                self.table.lock().unwrap().retain(|_, f| f.last_seen > cutoff);
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u64, bool)> {
        unsafe {
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
            let mut cbuf = [0u8; 128];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = &mut sll as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut _;
            msg.msg_controllen = cbuf.len() as _;
            let n = libc::recvmsg(self.fd, &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut ts = now_ns();
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPNS {
                    let t = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::timespec);
                    ts = t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            Ok((n as usize, ts, sll.sll_pkttype == libc::PACKET_OUTGOING as u8))
        }
    }

    fn handle(&mut self, pkt: &[u8], ts: u64, outgoing: bool) {
        let Some(p) = parse_ip_tcp(pkt) else { return };
        let (client, from_client) = if self.ports.contains(&p.dst_port) && !outgoing {
            (SocketAddr::new(p.src, p.src_port), true)
        } else if self.ports.contains(&p.src_port) {
            (SocketAddr::new(p.dst, p.dst_port), false)
        } else {
            return;
        };
        let syn = p.flags & 0x02 != 0;
        let ack = p.flags & 0x10 != 0;
        let rst = p.flags & 0x04 != 0;

        if from_client && syn && !ack {
            let mut table = self.table.lock().unwrap();
            if let Some(f) = table.get_mut(&client) {
                if f.synack_at.is_none() && f.syn_at.is_some() {
                    f.syn_retrans_at.push(ts);
                    f.last_seen = ts;
                    return;
                }
            }
            drop(table);
            let fields = syn_fields(&p);
            let p0f = self.p0f(pkt);
            let flow = Flow { syn_at: Some(ts), syn: Some(fields), p0f, last_seen: ts, ..Default::default() };
            self.table.lock().unwrap().insert(client, flow);
            return;
        }

        let mut table = self.table.lock().unwrap();
        let Some(f) = table.get_mut(&client) else { return };
        f.last_seen = ts;
        if rst {
            return;
        }
        if !from_client {
            if syn && ack && f.synack_at.is_none() {
                f.synack_at = Some(ts);
            }
            return;
        }
        if f.ack_at.is_none() && f.synack_at.is_some() && ack && !syn {
            f.ack_at = Some(ts);
            let opts = parse_options(p.options);
            f.ack = Some(AckFields { window: p.window, timestamps: opts.timestamps });
        }
        if f.first_data_at.is_none() && p.payload_len > 0 {
            f.first_data_at = Some(ts);
            f.first_data_len = Some(p.payload_len);
        }
    }

    fn p0f(&mut self, pkt: &[u8]) -> Option<P0fMatch> {
        let res = match pkt.first()? >> 4 {
            4 => huginn_net_tcp::process_ipv4_packet(&Ipv4Packet::new(pkt)?, &mut self.tracker, Some(&self.matcher)),
            6 => huginn_net_tcp::process_ipv6_packet(&Ipv6Packet::new(pkt)?, &mut self.tracker, Some(&self.matcher)),
            _ => return None,
        }
        .ok()?;
        let syn = res.syn?;
        let (quality, score) = match &syn.os_matched.quality {
            MatchQuality::Matched(r) => (
                match r {
                    MatchRank::Specific => "specific".to_string(),
                    MatchRank::Generic => "generic".to_string(),
                    MatchRank::Fuzzy(_) => "fuzzy".to_string(),
                },
                r.as_quality(),
            ),
            MatchQuality::NotMatched => ("not_matched".into(), 0.0),
            MatchQuality::Disabled => ("disabled".into(), 0.0),
        };
        let os = syn.os_matched.os.as_ref().map(|o| {
            let mut s = o.name.clone();
            if let Some(f) = &o.variant {
                s.push(' ');
                s.push_str(f);
            }
            s
        });
        Some(P0fMatch {
            os,
            os_kind: syn.os_matched.os.as_ref().and_then(|o| o.family.clone()),
            quality,
            score,
            dist: syn.os_matched.dist,
            signature: syn.sig.to_string(),
            mtu: res.mtu.as_ref().map(|m| m.mtu),
            link: res.mtu.as_ref().and_then(|m| m.link.link.clone()),
        })
    }
}

struct IpTcp<'a> {
    version: u8,
    src: IpAddr,
    dst: IpAddr,
    ttl: u8,
    df: bool,
    ip_id: u32,
    tos: u8,
    total_len: u16,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    window: u16,
    data_offset: u8,
    options: &'a [u8],
    payload_len: usize,
}

fn parse_ip_tcp(pkt: &[u8]) -> Option<IpTcp<'_>> {
    let v = pkt.first()? >> 4;
    let (src, dst, ttl, df, ip_id, tos, total_len, tcp) = match v {
        4 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() < ihl + 20 || pkt[9] != 6 {
                return None;
            }
            let total = u16::from_be_bytes([pkt[2], pkt[3]]);
            let end = (total as usize).min(pkt.len());
            (
                IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
                pkt[8],
                pkt[6] & 0x40 != 0,
                u16::from_be_bytes([pkt[4], pkt[5]]) as u32,
                pkt[1],
                total,
                &pkt[ihl..end],
            )
        }
        6 => {
            if pkt.len() < 60 || pkt[6] != 6 {
                return None;
            }
            let s: [u8; 16] = pkt[8..24].try_into().ok()?;
            let d: [u8; 16] = pkt[24..40].try_into().ok()?;
            let plen = u16::from_be_bytes([pkt[4], pkt[5]]);
            let end = (40 + plen as usize).min(pkt.len());
            let tc = ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4);
            let flow_label = ((pkt[1] as u32 & 0x0f) << 16) | ((pkt[2] as u32) << 8) | pkt[3] as u32;
            (
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                pkt[7],
                false,
                flow_label,
                tc,
                plen + 40,
                &pkt[40..end],
            )
        }
        _ => return None,
    };
    if tcp.len() < 20 {
        return None;
    }
    let doff = (tcp[12] >> 4) as usize * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    Some(IpTcp {
        version: v,
        src,
        dst,
        ttl,
        df,
        ip_id,
        tos,
        total_len,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        flags: tcp[13],
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        data_offset: doff as u8,
        options: &tcp[20..doff],
        payload_len: tcp.len() - doff,
    })
}

#[derive(Default)]
struct Opts {
    list: Vec<String>,
    mss: Option<u16>,
    wscale: Option<u8>,
    sack_perm: bool,
    timestamps: bool,
    tsval: Option<u32>,
}

fn parse_options(mut o: &[u8]) -> Opts {
    let mut r = Opts::default();
    while let Some(&kind) = o.first() {
        match kind {
            0 => {
                r.list.push("EOL".into());
                break;
            }
            1 => {
                r.list.push("NOP".into());
                o = &o[1..];
            }
            _ => {
                let Some(&len) = o.get(1) else { break };
                let len = len as usize;
                if len < 2 || o.len() < len {
                    r.list.push(format!("BAD({kind})"));
                    break;
                }
                let d = &o[2..len];
                match (kind, d.len()) {
                    (2, 2) => {
                        let v = u16::from_be_bytes([d[0], d[1]]);
                        r.mss = Some(v);
                        r.list.push(format!("MSS={v}"));
                    }
                    (3, 1) => {
                        r.wscale = Some(d[0]);
                        r.list.push(format!("WS={}", d[0]));
                    }
                    (4, 0) => {
                        r.sack_perm = true;
                        r.list.push("SACK_PERM".into());
                    }
                    (8, 8) => {
                        r.timestamps = true;
                        r.tsval = Some(u32::from_be_bytes([d[0], d[1], d[2], d[3]]));
                        r.list.push("TS".into());
                    }
                    (34, _) => r.list.push("TFO".into()),
                    _ => r.list.push(format!("OPT{kind}")),
                }
                o = &o[len..];
            }
        }
    }
    r
}

fn syn_fields(p: &IpTcp) -> SynFields {
    let o = parse_options(p.options);
    let initial_ttl: u16 = match p.ttl {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    };
    SynFields {
        ip_version: p.version,
        ttl: p.ttl,
        initial_ttl,
        hops: initial_ttl - p.ttl as u16,
        df: p.df,
        ip_id: p.ip_id,
        tos: p.tos,
        ip_ecn: p.tos & 0x03,
        ip_total_len: p.total_len,
        ece: p.flags & 0x40 != 0,
        cwr: p.flags & 0x80 != 0,
        window: p.window,
        data_offset: p.data_offset,
        options: o.list,
        mss: o.mss,
        wscale: o.wscale,
        sack_perm: o.sack_perm,
        timestamps: o.timestamps,
        tsval: o.tsval,
    }
}
