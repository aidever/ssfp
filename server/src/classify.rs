//! M3：判定浏览器所在的 OS，决定出口模板。
//!
//! 优先级：用户固定 > 明文 HTTP 的 User-Agent > JA4 对照表 > 客户端 SYN > 默认模板。
//! ClientHello 主要反映浏览器而非 OS（Chrome 在各系统上几乎相同），
//! 所以 JA4 只查表，不做推测；表由 M0 靶机用真实设备实测得到。

use std::collections::HashMap;

use fpcore::{Family, SynFields};
use serde::Serialize;

use crate::config::TemplateChoice;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Signals {
    /// 首包是 TLS ClientHello 时的 JA4（不记录 SNI，避免日志带上用户访问的站点）
    pub ja4: Option<String>,
    pub ua_family: Option<Family>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    User,
    /// 按设备访问的系统服务域名学到的
    Learned,
    Ua,
    Ja4,
    Syn,
    Default,
}

pub fn signals(first: &[u8]) -> Signals {
    let mut s = Signals::default();
    if first.len() > 5 && first[0] == 0x16 && first[1] == 0x03 {
        if let Ok(sig) = huginn_net_tls::parse_tls_client_hello(first) {
            s.ja4 = Some(sig.generate_ja4().full.value().to_string());
        }
    } else if let Some(ua) = http_user_agent(first) {
        s.ua_family = Family::from_user_agent(ua);
    }
    s
}

/// 只在首包像 HTTP/1.x 请求时找 User-Agent 头。
fn http_user_agent(b: &[u8]) -> Option<&str> {
    const METHODS: [&[u8]; 7] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH "];
    if !METHODS.iter().any(|m| b.starts_with(m)) {
        return None;
    }
    let head_end = b.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(b.len());
    let head = std::str::from_utf8(&b[..head_end]).ok()?;
    head.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case("user-agent").then(|| v.trim())
    })
}

pub fn decide(
    user: Option<TemplateChoice>,
    default: TemplateChoice,
    sig: &Signals,
    syn: Option<&SynFields>,
    ja4_table: &HashMap<String, Family>,
) -> (Family, Source) {
    let (choice, fixed_source) = match user {
        Some(c) => (c, Source::User),
        None => (default, Source::Default),
    };
    if let TemplateChoice::Fixed(f) = choice {
        return (f, fixed_source);
    }
    if let Some(f) = sig.ua_family {
        return (f, Source::Ua);
    }
    if let Some(f) = sig.ja4.as_ref().and_then(|j| ja4_table.get(j)) {
        return (*f, Source::Ja4);
    }
    match syn.map(Family::guess_from_syn) {
        Some(f) if f != Family::None => (f, Source::Syn),
        _ => (Family::None, Source::Default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ua_from_http() {
        let req = b"GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X)\r\n\r\n";
        assert_eq!(signals(req).ua_family, Some(Family::Apple));
        assert_eq!(signals(b"\x00\x01garbage").ua_family, None);
    }

    #[test]
    fn priority() {
        let mut t = HashMap::new();
        t.insert("JA4X".to_string(), Family::Apple);
        let win_syn = SynFields { initial_ttl: 128, ..Default::default() };
        let sig = Signals { ja4: Some("JA4X".into()), ua_family: None };
        // 固定模板优先
        assert_eq!(decide(Some(TemplateChoice::Fixed(Family::Linux)), TemplateChoice::Auto, &sig, Some(&win_syn), &t).1, Source::User);
        // auto：JA4 表命中先于 SYN
        assert_eq!(decide(None, TemplateChoice::Auto, &sig, Some(&win_syn), &t), (Family::Apple, Source::Ja4));
        // JA4 不在表里 → SYN
        let sig2 = Signals { ja4: Some("other".into()), ua_family: None };
        assert_eq!(decide(None, TemplateChoice::Auto, &sig2, Some(&win_syn), &t), (Family::Windows, Source::Syn));
        // 什么都没有 → 不改
        assert_eq!(decide(None, TemplateChoice::Auto, &Signals::default(), None, &t), (Family::None, Source::Default));
    }
}
