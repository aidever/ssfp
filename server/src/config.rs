use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Context as _;
use fpcore::Family;
use serde::Deserialize;

/// 模板选择：固定某个 OS，或 auto（按客户端特征自动判定）
#[derive(Debug, Clone, Copy)]
pub enum TemplateChoice {
    Fixed(Family),
    Auto,
}

impl TemplateChoice {
    pub fn name(&self) -> String {
        match self {
            Self::Auto => "auto".into(),
            Self::Fixed(f) => serde_json::to_value(f).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if s.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        Family::from_name(s)
            .map(Self::Fixed)
            .with_context(|| format!("未知模板 {s}，可选 auto / windows / apple / linux / none"))
    }
}

#[derive(Debug, Deserialize)]
pub struct UserCfg {
    pub name: String,
    /// SS2022 用户密钥（base64）
    pub password: String,
    /// 覆盖默认模板，如软路由后面的用户固定为 windows
    #[serde(default)]
    template: Option<String>,
    /// block_private 开启时仍允许该用户访问的内网地址，如面板 "10.0.0.1:8080"
    #[serde(default)]
    pub private_allow: Vec<SocketAddr>,
}

impl UserCfg {
    pub fn template_name(&self) -> Option<&str> {
        self.template.as_deref()
    }

    pub fn template(&self) -> anyhow::Result<Option<TemplateChoice>> {
        self.template.as_deref().map(TemplateChoice::parse).transpose()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: SocketAddr,
    method: String,
    /// SS2022 服务端 PSK（base64）
    password: String,
    #[serde(default)]
    users: Vec<UserCfg>,
    #[serde(default)]
    egress_v4: Option<Ipv4Addr>,
    #[serde(default)]
    egress_v6: Option<Ipv6Addr>,
    #[serde(default = "d_wait")]
    first_data_wait_ms: u64,
    #[serde(default = "d_tpl")]
    default_template: String,
    #[serde(default = "d_true")]
    block_private: bool,
    /// 给出站 socket 打 SO_MARK（需要 CAP_NET_ADMIN），供 M4 的 eBPF 识别
    #[serde(default)]
    set_mark: bool,
    #[serde(default = "d_connect")]
    connect_timeout_s: u64,
    #[serde(default)]
    log: Option<String>,
    /// 在这个网卡的 egress 挂 eBPF 改写 SYN（M4）；设置后自动开启 set_mark
    #[serde(default)]
    syn_rewrite_iface: Option<String>,
    /// 该网卡上 L3 头的偏移：以太网 14，tun/wireguard 等无二层头的设备 0
    #[serde(default = "d_l3")]
    syn_rewrite_l3_offset: u32,
    /// 开启 UDP 中继
    #[serde(default = "d_true")]
    udp: bool,
    /// 丢弃目标端口 443 的 UDP（QUIC），让浏览器走 TCP
    #[serde(default = "d_true")]
    block_quic: bool,
    #[serde(default = "d_idle")]
    udp_idle_s: u64,
    /// 管理看板 + 订阅（默认只听本机；也可设为只能经代理访问的内网地址，如 10.255.0.1:43480）
    #[serde(default = "d_console")]
    console_listen: Option<SocketAddr>,
    /// 用户 / 设备 / 流量数据目录
    #[serde(default = "d_state")]
    state_dir: String,
    /// 订阅 / 链接里写的服务器地址；不填时取出口网卡的 IPv4
    #[serde(default)]
    public_host: Option<String>,
    /// JA4 → OS 对照表，如 "t13d2014h2_xxx_yyy" = "apple"
    #[serde(default)]
    ja4: HashMap<String, String>,
}

fn d_wait() -> u64 {
    50
}
fn d_tpl() -> String {
    "none".into()
}
fn d_true() -> bool {
    true
}
fn d_console() -> Option<SocketAddr> {
    Some("127.0.0.1:43480".parse().unwrap())
}
fn d_state() -> String {
    "/var/lib/ssfp".into()
}
fn d_idle() -> u64 {
    120
}
fn d_l3() -> u32 {
    14
}
fn d_connect() -> u64 {
    10
}

#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub method: String,
    pub password: String,
    pub users: Vec<UserCfg>,
    pub egress_v4: Option<Ipv4Addr>,
    pub egress_v6: Option<Ipv6Addr>,
    pub first_data_wait_ms: u64,
    pub default_template: TemplateChoice,
    pub block_private: bool,
    pub set_mark: bool,
    pub connect_timeout_s: u64,
    pub log: Option<String>,
    pub ja4: HashMap<String, Family>,
    pub syn_rewrite_iface: Option<String>,
    pub syn_rewrite_l3_offset: u32,
    pub udp: bool,
    pub block_quic: bool,
    pub udp_idle_s: u64,
    pub console_listen: Option<SocketAddr>,
    pub state_dir: String,
    pub public_host: Option<String>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("读取配置 {path}"))?;
        let r: RawConfig = toml::from_str(&text).with_context(|| format!("解析配置 {path}"))?;
        for u in &r.users {
            u.template()?;
        }
        let mut ja4 = HashMap::new();
        for (k, v) in &r.ja4 {
            let f = Family::from_name(v).with_context(|| format!("JA4 表里 {k} 的值 {v} 不是 windows / apple / linux"))?;
            ja4.insert(k.clone(), f);
        }
        Ok(Self {
            ja4,
            listen: r.listen,
            method: r.method,
            password: r.password,
            users: r.users,
            egress_v4: r.egress_v4,
            egress_v6: r.egress_v6,
            first_data_wait_ms: r.first_data_wait_ms.min(1000),
            default_template: TemplateChoice::parse(&r.default_template)?,
            block_private: r.block_private,
            set_mark: r.set_mark || r.syn_rewrite_iface.is_some(),
            syn_rewrite_iface: r.syn_rewrite_iface,
            syn_rewrite_l3_offset: r.syn_rewrite_l3_offset,
            connect_timeout_s: r.connect_timeout_s,
            log: r.log,
            udp: r.udp,
            block_quic: r.block_quic,
            udp_idle_s: r.udp_idle_s,
            console_listen: r.console_listen,
            state_dir: r.state_dir,
            public_host: r.public_host,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn example_config_parses() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/config.example.toml");
        let c = super::Config::load(p).expect("示例配置应能解析");
        assert!(c.console_listen.is_some());
        assert_eq!(c.state_dir, "/var/lib/ssfp");
        assert_eq!(c.users.len(), 2);
    }
}
