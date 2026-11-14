//! 流量统计：每台设备的累计字节、在线连接、按天历史；全局速率采样。
//!
//! - 转发时用 Counted 包住出站 socket：读 = 下行，写 = 上行
//! - 每 5 秒采样一次全局速率（保留 10 分钟），每 60 秒把增量记入当天并落盘 traffic.json

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::now_ms;

#[derive(Default)]
pub struct DevStats {
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub conns: AtomicI64,
    pub last_seen_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnInfo {
    pub id: u64,
    pub device_id: u32,
    pub device: String,
    pub target: String,
    pub template: Option<String>,
    pub template_source: Option<String>,
    pub udp: bool,
    pub started_ms: u64,
    #[serde(skip)]
    pub abort: Option<tokio::task::AbortHandle>,
    #[serde(skip)]
    pub stats: Option<Arc<ConnBytes>>,
}

#[derive(Default, Debug)]
pub struct ConnBytes {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

#[derive(Default, Serialize, Deserialize)]
struct Persist {
    /// 设备累计 (up, down)
    totals: HashMap<u32, (u64, u64)>,
    /// 日期 → 设备 → (up, down)
    days: BTreeMap<String, HashMap<u32, (u64, u64)>>,
}

pub struct Traffic {
    path: PathBuf,
    devs: RwLock<HashMap<u32, Arc<DevStats>>>,
    conns: Mutex<HashMap<u64, ConnInfo>>,
    next_conn: AtomicU64,
    persist: Mutex<Persist>,
    /// 上次记入"当天"时各设备的累计值
    last: Mutex<HashMap<u32, (u64, u64)>>,
    /// (时间, 上行 B/s, 下行 B/s)
    rate: Mutex<VecDeque<(u64, u64, u64)>>,
    rate_last: Mutex<(u64, u64)>,
    pub started_ms: u64,
}

/// 本地日期 YYYY-MM-DD
pub fn local_date(ms: u64) -> String {
    let t: i64 = (ms / 1000) as i64;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t as *const i64 as *const _, &mut tm) };
    format!("{:04}-{:02}-{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday)
}

impl Traffic {
    pub fn open(dir: &std::path::Path) -> Arc<Self> {
        let path = dir.join("traffic.json");
        let p: Persist = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let mut devs = HashMap::new();
        for (id, (u, d)) in &p.totals {
            let s = DevStats::default();
            s.up.store(*u, Relaxed);
            s.down.store(*d, Relaxed);
            devs.insert(*id, Arc::new(s));
        }
        let last = p.totals.clone();
        Arc::new(Self {
            path,
            devs: RwLock::new(devs),
            conns: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            persist: Mutex::new(p),
            last: Mutex::new(last),
            rate: Mutex::new(VecDeque::new()),
            rate_last: Mutex::new((0, 0)),
            started_ms: now_ms(),
        })
    }

    pub fn dev(&self, id: u32) -> Arc<DevStats> {
        if let Some(s) = self.devs.read().unwrap().get(&id) {
            return s.clone();
        }
        self.devs.write().unwrap().entry(id).or_default().clone()
    }

    pub fn dev_opt(&self, id: u32) -> Option<Arc<DevStats>> {
        self.devs.read().unwrap().get(&id).cloned()
    }

    pub fn forget(&self, id: u32) {
        self.devs.write().unwrap().remove(&id);
        let mut p = self.persist.lock().unwrap();
        p.totals.remove(&id);
        for d in p.days.values_mut() {
            d.remove(&id);
        }
        self.last.lock().unwrap().remove(&id);
    }

    pub fn open_conn(&self, mut c: ConnInfo) -> (u64, Arc<ConnBytes>) {
        let id = self.next_conn.fetch_add(1, Relaxed);
        c.id = id;
        let b = Arc::new(ConnBytes::default());
        c.stats = Some(b.clone());
        let s = self.dev(c.device_id);
        s.conns.fetch_add(1, Relaxed);
        s.last_seen_ms.store(now_ms(), Relaxed);
        self.conns.lock().unwrap().insert(id, c);
        (id, b)
    }

    pub fn set_abort(&self, id: u64, h: tokio::task::AbortHandle) {
        if let Some(c) = self.conns.lock().unwrap().get_mut(&id) {
            c.abort = Some(h);
        }
    }

    pub fn update_conn(&self, id: u64, f: impl FnOnce(&mut ConnInfo)) {
        if let Some(c) = self.conns.lock().unwrap().get_mut(&id) {
            f(c);
        }
    }

    pub fn close_conn(&self, id: u64) {
        if let Some(c) = self.conns.lock().unwrap().remove(&id) {
            let s = self.dev(c.device_id);
            s.conns.fetch_sub(1, Relaxed);
            s.last_seen_ms.store(now_ms(), Relaxed);
        }
    }

    /// 断开某台设备（或某用户全部设备）的现有连接
    pub fn kill(&self, pred: impl Fn(&ConnInfo) -> bool) -> usize {
        let m = self.conns.lock().unwrap();
        let mut n = 0;
        for c in m.values().filter(|c| pred(c)) {
            if let Some(h) = &c.abort {
                h.abort();
                n += 1;
            }
        }
        n
    }

    pub fn conns(&self) -> Vec<serde_json::Value> {
        let m = self.conns.lock().unwrap();
        let mut v: Vec<_> = m.values().collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.started_ms));
        v.iter()
            .take(300)
            .map(|c| {
                let mut j = serde_json::to_value(c).unwrap_or_default();
                if let Some(b) = &c.stats {
                    j["up"] = b.up.load(Relaxed).into();
                    j["down"] = b.down.load(Relaxed).into();
                }
                j
            })
            .collect()
    }

    pub fn conn_count(&self) -> usize {
        self.conns.lock().unwrap().len()
    }

    fn sum(&self) -> (u64, u64) {
        self.devs.read().unwrap().values().fold((0, 0), |a, s| (a.0 + s.up.load(Relaxed), a.1 + s.down.load(Relaxed)))
    }

    /// 每 5 秒调用
    pub fn sample(&self) {
        let (u, d) = self.sum();
        let mut last = self.rate_last.lock().unwrap();
        let (du, dd) = if last.0 == 0 && last.1 == 0 { (0, 0) } else { (u.saturating_sub(last.0) / 5, d.saturating_sub(last.1) / 5) };
        *last = (u, d);
        let mut r = self.rate.lock().unwrap();
        r.push_back((now_ms(), du, dd));
        while r.len() > 120 {
            r.pop_front();
        }
    }

    pub fn rate(&self) -> Vec<(u64, u64, u64)> {
        self.rate.lock().unwrap().iter().copied().collect()
    }

    /// 每 60 秒调用：增量记入当天并落盘
    pub fn roll(&self) {
        let today = local_date(now_ms());
        let devs: Vec<(u32, u64, u64)> =
            self.devs.read().unwrap().iter().map(|(id, s)| (*id, s.up.load(Relaxed), s.down.load(Relaxed))).collect();
        let mut last = self.last.lock().unwrap();
        let mut p = self.persist.lock().unwrap();
        for (id, u, d) in devs {
            let (lu, ld) = last.get(&id).copied().unwrap_or((0, 0));
            let (du, dd) = (u.saturating_sub(lu), d.saturating_sub(ld));
            if du + dd > 0 {
                let e = p.days.entry(today.clone()).or_default().entry(id).or_default();
                e.0 += du;
                e.1 += dd;
            }
            last.insert(id, (u, d));
            p.totals.insert(id, (u, d));
        }
        while p.days.len() > 100 {
            let k = p.days.keys().next().cloned().unwrap();
            p.days.remove(&k);
        }
        if let Ok(b) = serde_json::to_vec(&*p) {
            let tmp = self.path.with_extension("json.tmp");
            if std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    /// 某设备在给定日期集合内的 (up, down)，含当天尚未记入的部分
    pub fn usage(&self, id: u32, dates: &[String]) -> (u64, u64) {
        let today = local_date(now_ms());
        let p = self.persist.lock().unwrap();
        let mut t = (0, 0);
        for d in dates {
            if let Some(v) = p.days.get(d).and_then(|m| m.get(&id)) {
                t.0 += v.0;
                t.1 += v.1;
            }
        }
        if dates.contains(&today) {
            if let Some(s) = self.dev_opt(id) {
                let (lu, ld) = self.last.lock().unwrap().get(&id).copied().unwrap_or((0, 0));
                t.0 += s.up.load(Relaxed).saturating_sub(lu);
                t.1 += s.down.load(Relaxed).saturating_sub(ld);
            }
        }
        t
    }

    /// 最近 n 天（含今天）的日期，旧 → 新
    pub fn last_days(n: usize) -> Vec<String> {
        let now = now_ms();
        let mut v: Vec<String> = (0..n).map(|i| local_date(now - i as u64 * 86_400_000)).collect();
        v.dedup();
        v.reverse();
        v
    }

    pub fn month_dates() -> Vec<String> {
        let today = local_date(now_ms());
        let prefix = &today[..8];
        Self::last_days(31).into_iter().filter(|d| d.starts_with(prefix)).collect()
    }
}

/// 计数包装：读 = 下行，写 = 上行
pub struct Counted<S> {
    pub inner: S,
    dev: Arc<DevStats>,
    conn: Arc<ConnBytes>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, dev: Arc<DevStats>, conn: Arc<ConnBytes>) -> Self {
        Self { inner, dev, conn }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            self.dev.down.fetch_add(n, Relaxed);
            self.conn.down.fetch_add(n, Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.dev.up.fetch_add(n as u64, Relaxed);
            self.conn.up.fetch_add(n as u64, Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
