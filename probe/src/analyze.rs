//! 把各层观测归一到 OS 家族，并给出一致性与时序判定。

use serde::Serialize;

use crate::capture::Flow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Windows,
    Apple,
    Linux,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsGuess {
    pub family: Family,
    /// 具体名称，如 "iOS"、"Windows 10/11"、"Linux 3.11+"
    pub label: String,
    /// 依据，如 "p0f specific" / "初始 TTL 128" / "UA" / "Sec-CH-UA-Platform"
    pub source: String,
}

pub fn family_of(name: &str) -> Family {
    let n = name.to_ascii_lowercase();
    if n.contains("windows") {
        Family::Windows
    } else if n.contains("mac") || n.contains("ios") || n.contains("iphone") || n.contains("ipad") || n.contains("apple") {
        Family::Apple
    } else if n.contains("linux") || n.contains("android") || n.contains("chrome os") || n.contains("cros") {
        Family::Linux
    } else {
        Family::Unknown
    }
}

/// TCP 层：优先 p0f 匹配，匹配不上时用初始 TTL 兜底。
pub fn tcp_os(flow: &Flow) -> OsGuess {
    if let Some(p) = &flow.p0f {
        if let Some(os) = &p.os {
            let fam = family_of(os).or(p.os_kind.as_deref().map(family_of).unwrap_or(Family::Unknown));
            if fam != Family::Unknown {
                return OsGuess { family: fam, label: os.clone(), source: format!("p0f {}", p.quality) };
            }
        }
    }
    if let Some(s) = &flow.syn {
        let (fam, label) = match s.initial_ttl {
            128 => (Family::Windows, "Windows（按 TTL）"),
            64 if !s.timestamps => (Family::Unknown, "TTL 64，无时间戳"),
            64 => (Family::Unknown, "类 Unix（TTL 64）"),
            _ => (Family::Unknown, "未知"),
        };
        return OsGuess { family: fam, label: label.into(), source: format!("初始 TTL {}", s.initial_ttl) };
    }
    OsGuess { family: Family::Unknown, label: "未抓到 SYN".into(), source: "-".into() }
}

impl Family {
    fn or(self, other: Family) -> Family {
        if self == Family::Unknown { other } else { self }
    }
}

/// 浏览器自报：Sec-CH-UA-Platform 优先于 UA 字符串。
pub fn http_os(ua: Option<&str>, ch_platform: Option<&str>) -> OsGuess {
    if let Some(p) = ch_platform {
        let p = p.trim_matches('"');
        if !p.is_empty() {
            return OsGuess { family: family_of(p), label: p.to_string(), source: "Sec-CH-UA-Platform".into() };
        }
    }
    let Some(ua) = ua else {
        return OsGuess { family: Family::Unknown, label: "无 UA".into(), source: "-".into() };
    };
    let label = if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Windows NT") {
        "Windows"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        "macOS"
    } else if ua.contains("CrOS") {
        "ChromeOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "未知"
    };
    OsGuess { family: family_of(label), label: label.into(), source: "User-Agent".into() }
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// "match" | "mismatch" | "unknown"
    pub os_consistency: &'static str,
    pub os_note: String,
    /// "ok" | "suspicious" | "unknown"
    pub rtt: &'static str,
    pub rtt_note: String,
    /// "ok" | "suspicious" | "unknown"
    pub first_data_gap: &'static str,
    pub gap_note: String,
}

pub fn verdict(tcp: &OsGuess, http: &OsGuess, tcp_rtt_ms: Option<f64>, app_rtt_ms: Option<f64>, gap_ms: Option<f64>) -> Verdict {
    let (os_consistency, os_note) = match (tcp.family, http.family) {
        (Family::Unknown, _) | (_, Family::Unknown) => ("unknown", "有一层无法判断 OS".to_string()),
        (a, b) if a == b => ("match", "TCP 层与浏览器自报的 OS 属于同一家族".to_string()),
        (a, b) => ("mismatch", format!("TCP 层像 {a:?}，浏览器自报 {b:?}")),
    };
    let (rtt, rtt_note) = match (tcp_rtt_ms, app_rtt_ms) {
        (Some(t), Some(a)) => {
            let extra = a - t;
            if extra > 30.0 && a > t * 2.0 {
                ("suspicious", format!("应用层 RTT 比 TCP 握手 RTT 多 {extra:.0} ms，像经过了代理或隧道"))
            } else {
                ("ok", format!("两者相差 {extra:.0} ms，在正常范围内"))
            }
        }
        _ => ("unknown", "缺少 TCP 或应用层 RTT".to_string()),
    };
    let (first_data_gap, gap_note) = match (gap_ms, tcp_rtt_ms) {
        (Some(g), t) => {
            let limit = (t.unwrap_or(0.0) * 0.5).max(10.0);
            if g > limit {
                ("suspicious", format!("握手完成后 {g:.1} ms 才收到首包，浏览器直连通常立即发送"))
            } else {
                ("ok", format!("握手完成后 {g:.1} ms 收到首包"))
            }
        }
        _ => ("unknown", "未抓到首包时间".to_string()),
    };
    Verdict { os_consistency, os_note, rtt, rtt_note, first_data_gap, gap_note }
}
