//! 出口指纹模板。M2 只落地 socket 选项能做到的部分（TTL、wscale、MSS、mark），
//! 窗口值、选项顺序、时间戳、ECN 由 M4 的 eBPF 按 mark 改写。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Windows,
    Apple,
    Linux,
    /// Linux 内核，但窗口 / wscale 不同（实测 Android 10 Chrome：65535、ws 9）
    Android,
    /// 不改动，使用内核默认
    None,
}

impl Family {
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "windows" => Some(Self::Windows),
            "apple" | "macos" | "ios" => Some(Self::Apple),
            "linux" => Some(Self::Linux),
            "android" => Some(Self::Android),
            "none" | "off" => Some(Self::None),
            _ => None,
        }
    }

    /// 从 User-Agent 判断（iPhone/iPad 先于 Mac，Android 先于 Linux）
    pub fn from_user_agent(ua: &str) -> Option<Self> {
        if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("Macintosh") || ua.contains("Mac OS X") {
            Some(Self::Apple)
        } else if ua.contains("Windows NT") {
            Some(Self::Windows)
        } else if ua.contains("Android") {
            Some(Self::Android)
        } else if ua.contains("CrOS") || ua.contains("Linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }

    /// 由客户端 SYN 粗判（M3 会换成 ClientHello 优先的完整判定）
    pub fn guess_from_syn(s: &crate::SynFields) -> Self {
        match (s.initial_ttl, s.timestamps, s.layout().as_str()) {
            (128, _, _) => Self::Windows,
            (64, true, l) if l.starts_with("MSS,NOP,WS,NOP,NOP,TS") => Self::Apple,
            (64, _, l) if l.starts_with("MSS,SACK_PERM,TS") && s.window == 65535 && s.wscale.unwrap_or(0) >= 8 => Self::Android,
            (64, _, l) if l.starts_with("MSS,SACK_PERM,TS") => Self::Linux,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Template {
    pub family: Family,
    /// 交给 eBPF 识别的 SO_MARK；0 表示不改写
    pub mark: u32,
    pub ttl: Option<u32>,
    /// 目标 wscale，靠 TCP_WINDOW_CLAMP 让内核选出
    pub wscale: Option<u8>,
    /// SYN 里的窗口值（M4 eBPF 改写）
    pub syn_window: Option<u16>,
    pub timestamps: Option<bool>,
    /// 选项布局（M4 eBPF 改写）
    pub layout: Option<&'static str>,
}

/// mark 的高 16 位固定为 0x5f50（"_P"），低位是模板编号，避免和其他 fwmark 冲突。
pub const MARK_BASE: u32 = 0x5f50_0000;

impl Template {
    pub fn of(family: Family) -> Self {
        match family {
            Family::Windows => Self {
                family,
                mark: MARK_BASE | 1,
                ttl: Some(128),
                wscale: Some(8),
                // 真机实测 65535（2026-11-13，Windows 10/11 Chrome）
                syn_window: Some(65535),
                timestamps: Some(false),
                layout: Some("MSS,NOP,WS,NOP,NOP,SACK_PERM"),
            },
            Family::Apple => Self {
                family,
                mark: MARK_BASE | 2,
                ttl: Some(64),
                wscale: Some(6),
                syn_window: Some(65535),
                timestamps: Some(true),
                layout: Some("MSS,NOP,WS,NOP,NOP,TS,SACK_PERM,EOL"),
            },
            Family::Linux => Self {
                family,
                mark: MARK_BASE | 3,
                ttl: Some(64),
                wscale: Some(7),
                syn_window: Some(64240),
                timestamps: Some(true),
                layout: Some("MSS,SACK_PERM,TS,NOP,WS"),
            },
            Family::Android => Self {
                family,
                mark: MARK_BASE | 4,
                ttl: Some(64),
                wscale: Some(9),
                syn_window: Some(65535),
                timestamps: Some(true),
                layout: Some("MSS,SACK_PERM,TS,NOP,WS"),
            },
            Family::None => Self {
                family,
                mark: 0,
                ttl: None,
                wscale: None,
                syn_window: None,
                timestamps: None,
                layout: None,
            },
        }
    }

    /// 让 Linux 选出目标 wscale 的 TCP_WINDOW_CLAMP 值：
    /// 内核按 ilog2(min(space, clamp)) - 15 计算 wscale，取区间中点。
    /// 前提是 max(tcp_rmem[2], rmem_max) 不小于这个值，否则 wscale 会更小。
    pub fn window_clamp(&self) -> Option<u32> {
        let ws = self.wscale?;
        Some(3u32 << (ws as u32 + 14))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ua_families() {
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15";
        let android = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/142.0 Mobile";
        assert_eq!(Family::from_user_agent(iphone), Some(Family::Apple));
        assert_eq!(Family::from_user_agent(android), Some(Family::Android));
        assert_eq!(Family::from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), Some(Family::Windows));
        assert_eq!(Family::from_user_agent("curl/8.5.0"), None);
    }

    #[test]
    fn clamp_hits_target_wscale() {
        for f in [Family::Windows, Family::Apple, Family::Linux, Family::Android] {
            let t = Template::of(f);
            let c = t.window_clamp().unwrap();
            assert_eq!(c.ilog2() - 15, t.wscale.unwrap() as u32, "{f:?}");
        }
    }
}
