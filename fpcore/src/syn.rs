//! 解析一个完整的 IPv4/IPv6 + TCP SYN 报文（来自 TCP_SAVED_SYN 或抓包）。

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct SynFields {
    pub ip_version: u8,
    pub ttl: u8,
    /// 由观测 TTL 推断的初始 TTL（32 / 64 / 128 / 255）
    pub initial_ttl: u16,
    pub df: bool,
    pub ip_id: u32,
    pub tos: u8,
    pub ece: bool,
    pub cwr: bool,
    pub window: u16,
    /// 按出现顺序，如 ["MSS=1460","NOP","WS=8","NOP","NOP","SACK_PERM"]
    pub options: Vec<String>,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_perm: bool,
    pub timestamps: bool,
}

impl SynFields {
    /// 只保留选项名的布局，如 "MSS,NOP,WS,NOP,NOP,SACK_PERM"
    pub fn layout(&self) -> String {
        self.options.iter().map(|o| o.split('=').next().unwrap_or("")).collect::<Vec<_>>().join(",")
    }
}

pub fn initial_ttl(ttl: u8) -> u16 {
    match ttl {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// 返回 None 表示不是可解析的 TCP SYN。
pub fn parse_syn(pkt: &[u8]) -> Option<SynFields> {
    let v = pkt.first()? >> 4;
    let (ttl, df, ip_id, tos, tcp) = match v {
        4 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() < ihl + 20 || pkt[9] != 6 {
                return None;
            }
            (pkt[8], pkt[6] & 0x40 != 0, u16::from_be_bytes([pkt[4], pkt[5]]) as u32, pkt[1], &pkt[ihl..])
        }
        6 => {
            if pkt.len() < 60 || pkt[6] != 6 {
                return None;
            }
            let tc = ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4);
            let flow = ((pkt[1] as u32 & 0x0f) << 16) | ((pkt[2] as u32) << 8) | pkt[3] as u32;
            (pkt[7], false, flow, tc, &pkt[40..])
        }
        _ => return None,
    };
    let doff = (tcp.get(12)? >> 4) as usize * 4;
    if doff < 20 || tcp.len() < doff || tcp[13] & 0x02 == 0 {
        return None;
    }
    let mut f = SynFields {
        ip_version: v,
        ttl,
        initial_ttl: initial_ttl(ttl),
        df,
        ip_id,
        tos,
        ece: tcp[13] & 0x40 != 0,
        cwr: tcp[13] & 0x80 != 0,
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        ..Default::default()
    };
    let mut o = &tcp[20..doff];
    while let Some(&kind) = o.first() {
        match kind {
            0 => {
                f.options.push("EOL".into());
                break;
            }
            1 => {
                f.options.push("NOP".into());
                o = &o[1..];
            }
            _ => {
                let len = *o.get(1)? as usize;
                if len < 2 || o.len() < len {
                    f.options.push(format!("BAD({kind})"));
                    break;
                }
                let d = &o[2..len];
                match (kind, d.len()) {
                    (2, 2) => {
                        let m = u16::from_be_bytes([d[0], d[1]]);
                        f.mss = Some(m);
                        f.options.push(format!("MSS={m}"));
                    }
                    (3, 1) => {
                        f.wscale = Some(d[0]);
                        f.options.push(format!("WS={}", d[0]));
                    }
                    (4, 0) => {
                        f.sack_perm = true;
                        f.options.push("SACK_PERM".into());
                    }
                    (8, 8) => {
                        f.timestamps = true;
                        f.options.push("TS".into());
                    }
                    (34, _) => f.options.push("TFO".into()),
                    _ => f.options.push(format!("OPT{kind}")),
                }
                o = &o[len..];
            }
        }
    }
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_syn() {
        // 45 TTL，DF，win 64240，MSS,SACK_PERM,TS,NOP,WS=7（取自一台 Linux 服务器的实测 SYN，地址已换成文档保留地址）
        let mut p = vec![
            0x45, 0x28, 0x00, 0x3c, 0x2c, 0xa2, 0x40, 0x00, 45, 6, 0, 0, 198, 51, 100, 17, 203, 0, 113, 179,
            0xc1, 0x34, 0x20, 0xfb, 0, 0, 0, 1, 0, 0, 0, 0, 0xa0, 0x02, 0xfa, 0xf0, 0, 0, 0, 0,
        ];
        p.extend_from_slice(&[2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7]);
        let f = parse_syn(&p).unwrap();
        assert_eq!(f.initial_ttl, 64);
        assert!(f.df);
        assert_eq!(f.window, 64240);
        assert_eq!(f.layout(), "MSS,SACK_PERM,TS,NOP,WS");
        assert_eq!(f.wscale, Some(7));
        assert!(f.timestamps);
    }
}
