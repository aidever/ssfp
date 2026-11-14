//! 用户 / 设备存储：/var/lib/ssfp/state.json。
//!
//! 一个用户可以有多台设备，每台设备一把 SS2022 用户密钥（uPSK），密钥 → 设备 → 模板。
//! 改动立即生效：重建 ServerUserManager 快照，新连接按新快照验证；停用的设备现有连接由调用方断开。

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Context as _;
use fpcore::Family;
use serde::{Deserialize, Serialize};
use shadowsocks::config::{ServerUser, ServerUserManager};

use crate::config::TemplateChoice;
use crate::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub name: String,
    /// 订阅地址里的随机令牌
    pub token: String,
    pub enabled: bool,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Learned {
    /// 按访问的系统服务域名累计的命中次数
    pub hits: BTreeMap<String, u64>,
    pub family: Option<Family>,
    pub hint: Option<String>,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: u32,
    pub user_id: u32,
    pub name: String,
    /// base64 用户密钥
    pub key: String,
    /// auto / windows / apple / android / linux / none
    pub template: String,
    pub enabled: bool,
    #[serde(default)]
    pub private_allow: Vec<SocketAddr>,
    #[serde(default)]
    pub learned: Learned,
    pub created_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Data {
    pub next_id: u32,
    pub users: Vec<User>,
    pub devices: Vec<Device>,
}

/// 一台可用设备的运行时信息（按密钥查）
#[derive(Debug, Clone)]
pub struct DevInfo {
    pub id: u32,
    pub user: String,
    pub name: String,
    pub template: TemplateChoice,
    pub learned: Option<Family>,
    pub private_allow: Vec<SocketAddr>,
}

impl DevInfo {
    pub fn label(&self) -> String {
        format!("{}/{}", self.user, self.name)
    }
}

pub struct Snapshot {
    pub users: Option<Arc<ServerUserManager>>,
    pub by_key: HashMap<Vec<u8>, DevInfo>,
}

pub struct Store {
    path: PathBuf,
    key_len: usize,
    data: Mutex<Data>,
    snap: RwLock<Arc<Snapshot>>,
    changed: tokio::sync::watch::Sender<u64>,
    dirty: std::sync::atomic::AtomicBool,
}

pub fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for ch in s.trim().bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    let r = unsafe { libc::getrandom(b.as_mut_ptr() as *mut _, n, 0) };
    assert_eq!(r as usize, n, "getrandom");
    b
}

pub fn random_token() -> String {
    random_bytes(12).iter().map(|b| format!("{b:02x}")).collect()
}

impl Store {
    /// 读取或新建；新建时把配置文件里的 [[users]] 导入到用户"默认"下
    pub fn open(dir: &Path, key_len: usize, import: &[crate::config::UserCfg]) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(dir).with_context(|| format!("创建 {}", dir.display()))?;
        let path = dir.join("state.json");
        let data = if path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&path)?).with_context(|| format!("解析 {}", path.display()))?
        } else {
            let mut d = Data { next_id: 1, ..Default::default() };
            if !import.is_empty() {
                let uid = d.next_id;
                d.next_id += 1;
                d.users.push(User { id: uid, name: "默认".into(), token: random_token(), enabled: true, created_ms: now_ms() });
                for u in import {
                    let id = d.next_id;
                    d.next_id += 1;
                    d.devices.push(Device {
                        id,
                        user_id: uid,
                        name: u.name.clone(),
                        key: u.password.clone(),
                        template: u.template_name().unwrap_or("auto").to_string(),
                        enabled: true,
                        private_allow: u.private_allow.clone(),
                        learned: Learned::default(),
                        created_ms: now_ms(),
                    });
                }
            }
            d
        };
        let (tx, _) = tokio::sync::watch::channel(0);
        let s = Arc::new(Self {
            path,
            key_len,
            data: Mutex::new(data),
            snap: RwLock::new(Arc::new(Snapshot { users: None, by_key: HashMap::new() })),
            changed: tx,
            dirty: false.into(),
        });
        s.commit()?;
        Ok(s)
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.read().unwrap().clone()
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn key_len(&self) -> usize {
        self.key_len
    }

    pub fn with<R>(&self, f: impl FnOnce(&Data) -> R) -> R {
        f(&self.data.lock().unwrap())
    }

    /// 修改数据并保存、重建快照
    pub fn update<R>(&self, f: impl FnOnce(&mut Data) -> anyhow::Result<R>) -> anyhow::Result<R> {
        let r = {
            let mut d = self.data.lock().unwrap();
            f(&mut d)?
        };
        self.commit()?;
        Ok(r)
    }

    fn commit(&self) -> anyhow::Result<()> {
        let d = self.data.lock().unwrap();
        let mut um = ServerUserManager::new();
        let mut by_key = HashMap::new();
        for dev in &d.devices {
            let Some(u) = d.users.iter().find(|u| u.id == dev.user_id) else { continue };
            if !dev.enabled || !u.enabled {
                continue;
            }
            let Some(k) = b64_decode(&dev.key).filter(|k| k.len() == self.key_len) else {
                eprintln!("设备 {}/{} 的密钥长度不对，已跳过", u.name, dev.name);
                continue;
            };
            let su = ServerUser::new(format!("{}/{}", u.name, dev.name), k.clone());
            um.add_user(su);
            by_key.insert(
                k,
                DevInfo {
                    id: dev.id,
                    user: u.name.clone(),
                    name: dev.name.clone(),
                    template: TemplateChoice::parse(&dev.template).unwrap_or(TemplateChoice::Auto),
                    learned: dev.learned.family,
                    private_allow: dev.private_allow.clone(),
                },
            );
        }
        self.save_locked(&d)?;
        drop(d);
        *self.snap.write().unwrap() = Arc::new(Snapshot { users: Some(Arc::new(um)), by_key });
        self.changed.send_modify(|v| *v += 1);
        Ok(())
    }

    fn save_locked(&self, d: &Data) -> anyhow::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(d)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// 自动学习：设备访问了某个系统专属域名
    pub fn learn(&self, dev_id: u32, family: Family, host: &str) {
        let mut d = self.data.lock().unwrap();
        let Some(dev) = d.devices.iter_mut().find(|x| x.id == dev_id) else { return };
        let name = serde_json::to_value(family).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        *dev.learned.hits.entry(name).or_default() += 1;
        let best = dev
            .learned
            .hits
            .iter()
            .max_by_key(|(_, n)| **n)
            .and_then(|(k, _)| Family::from_name(k));
        let changed = best != dev.learned.family;
        dev.learned.family = best;
        if best == Some(family) {
            dev.learned.hint = Some(host.to_string());
            dev.learned.at_ms = now_ms();
        }
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(d);
        if changed {
            let _ = self.commit();
        }
    }

    /// 定期把学习计数落盘
    pub fn flush(&self) {
        if self.dirty.swap(false, std::sync::atomic::Ordering::Relaxed) {
            let d = self.data.lock().unwrap();
            let _ = self.save_locked(&d);
        }
    }

    pub fn new_key(&self) -> String {
        b64(&random_bytes(self.key_len))
    }
}

/// 系统专属的服务域名（连通性检测、系统更新、推送），用来给 auto 设备学习系统
pub fn hint_family(host: &str) -> Option<Family> {
    const H: &[(&str, Family)] = &[
        ("msftconnecttest.com", Family::Windows),
        ("msftncsi.com", Family::Windows),
        ("windowsupdate.com", Family::Windows),
        ("update.microsoft.com", Family::Windows),
        ("wns.windows.com", Family::Windows),
        ("delivery.mp.microsoft.com", Family::Windows),
        ("captive.apple.com", Family::Apple),
        ("push.apple.com", Family::Apple),
        ("mesu.apple.com", Family::Apple),
        ("gdmf.apple.com", Family::Apple),
        ("gateway.icloud.com", Family::Apple),
        ("connectivitycheck.gstatic.com", Family::Android),
        ("connectivitycheck.android.com", Family::Android),
        ("android.clients.google.com", Family::Android),
        ("android.googleapis.com", Family::Android),
        ("connectivity-check.ubuntu.com", Family::Linux),
        ("nmcheck.gnome.org", Family::Linux),
        ("network-test.debian.org", Family::Linux),
        ("networkcheck.kde.org", Family::Linux),
    ];
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    H.iter()
        .find(|(d, _)| h == *d || h.ends_with(&format!(".{d}")))
        .map(|(_, f)| *f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        for n in 0..40 {
            let v = random_bytes(n);
            assert_eq!(b64_decode(&b64(&v)).unwrap(), v);
        }
        assert_eq!(b64(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn hints() {
        assert_eq!(hint_family("www.msftconnecttest.com"), Some(Family::Windows));
        assert_eq!(hint_family("captive.apple.com."), Some(Family::Apple));
        assert_eq!(hint_family("example.com"), None);
        assert_eq!(hint_family("notcaptive.apple.com"), None);
    }
}
