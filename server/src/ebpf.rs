//! M4：加载 TC egress eBPF 程序，按 SO_MARK 改写出站 SYN 的窗口与选项布局。
//!
//! 程序随 ssfp 进程存在：进程退出时链接关闭，出站 SYN 自动恢复内核默认，不会残留。

use std::ffi::CString;

use anyhow::Context as _;
use aya::Ebpf;
use aya::maps::{Array, PerCpuArray};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use fpcore::{Family, Template};

static OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/syn_rewrite.o"));

const NONE: u8 = 0xff;

/// 与 bpf/syn_rewrite.bpf.c 的 struct tpl 一致（48 字节）
#[repr(C)]
#[derive(Clone, Copy)]
struct Tpl {
    window: u16,
    opt_len: u8,
    /// 以下三个偏移指向 opts 里"值"的起点（不是选项 kind 字节）
    mss_off: u8,
    ws_off: u8,
    ts_off: u8,
    pad: [u8; 2],
    opts: [u8; 40],
}

impl Default for Tpl {
    fn default() -> Self {
        Self { window: 0, opt_len: 0, mss_off: NONE, ws_off: NONE, ts_off: NONE, pad: [0; 2], opts: [0; 40] }
    }
}

unsafe impl aya::Pod for Tpl {}

const STAT_NAMES: [&str; 7] = ["marked", "rewritten", "not_syn", "unchanged", "parse_fail", "adjust_fail", "store_fail"];

/// Linux 内核自己发出的 SYN 选项布局，模板相同时不必改写
const KERNEL_LAYOUT: &str = "MSS,SACK_PERM,TS,NOP,WS";

/// 把模板的选项布局拼成字节，MSS / WS / TS 的值位置留空，由 eBPF 从原 SYN 填入。
fn encode(tpl: &Template) -> anyhow::Result<Tpl> {
    let mut t = Tpl { window: tpl.syn_window.unwrap_or(0), ..Default::default() };
    let Some(layout) = tpl.layout.filter(|l| *l != KERNEL_LAYOUT) else { return Ok(t) };
    let mut b: Vec<u8> = Vec::new();
    let mut eol = false;
    for name in layout.split(',') {
        match name {
            "EOL" => {
                b.push(0);
                eol = true;
            }
            "NOP" => b.push(1),
            "MSS" => {
                t.mss_off = b.len() as u8 + 2;
                b.extend_from_slice(&[2, 4, 0, 0]);
            }
            "WS" => {
                t.ws_off = b.len() as u8 + 2;
                b.extend_from_slice(&[3, 3, 0]);
            }
            "SACK_PERM" => b.extend_from_slice(&[4, 2]),
            "TS" => {
                t.ts_off = b.len() as u8 + 2;
                b.extend_from_slice(&[8, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
            }
            other => anyhow::bail!("未知选项 {other}"),
        }
    }
    // 补齐到 4 字节：EOL 之后补 0，否则补 NOP
    while b.len() % 4 != 0 {
        b.push(if eol { 0 } else { 1 });
    }
    anyhow::ensure!(b.len() <= 40, "模板 {:?} 的选项超过 40 字节", tpl.family);
    t.opt_len = b.len() as u8;
    t.opts[..b.len()].copy_from_slice(&b);
    Ok(t)
}

pub struct SynRewriter {
    bpf: Ebpf,
    last: Vec<u64>,
}

impl SynRewriter {
    pub fn attach(iface: &str, l3_offset: u32) -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load(OBJ).context("加载 eBPF 对象失败（需要 root 或 CAP_BPF + CAP_NET_ADMIN）")?;
        {
            let mut cfg: Array<_, u32> = Array::try_from(bpf.map_mut("config").context("缺少 config map")?)?;
            cfg.set(0, &l3_offset, 0)?;
        }
        {
            let mut tpls: Array<_, Tpl> = Array::try_from(bpf.map_mut("templates").context("缺少 templates map")?)?;
            for f in [Family::Windows, Family::Apple, Family::Linux, Family::Android] {
                let t = Template::of(f);
                tpls.set(t.mark & 0xffff, &encode(&t)?, 0)?;
            }
        }
        let name = CString::new(iface)?;
        // 6.6 以下内核走 netlink，需要 clsact；已存在时报错可忽略
        let _ = tc::qdisc_add_clsact(name.as_c_str());
        let prog: &mut SchedClassifier =
            bpf.program_mut("syn_rewrite").context("缺少 syn_rewrite 程序")?.try_into()?;
        prog.load().context("eBPF 验证失败")?;
        prog.attach(name.as_c_str(), TcAttachType::Egress).with_context(|| format!("挂到 {iface} egress 失败"))?;
        Ok(Self { bpf, last: vec![0; STAT_NAMES.len()] })
    }

    /// 启动以来的累计计数
    pub fn stats_total(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        if let Some(arr) = self.bpf.map("stats").and_then(|m| PerCpuArray::<_, u64>::try_from(m).ok()) {
            for (i, name) in STAT_NAMES.iter().enumerate() {
                let total: u64 = arr.get(&(i as u32), 0).map(|v| v.iter().sum()).unwrap_or(0);
                out.insert((*name).into(), total.into());
            }
        }
        out.into()
    }

    /// 返回自上次调用以来各计数的增量（全为 0 时返回 None）
    pub fn stats_delta(&mut self) -> Option<serde_json::Value> {
        let arr: PerCpuArray<_, u64> = PerCpuArray::try_from(self.bpf.map("stats")?).ok()?;
        let mut out = serde_json::Map::new();
        let mut any = false;
        for (i, name) in STAT_NAMES.iter().enumerate() {
            let total: u64 = arr.get(&(i as u32), 0).map(|v| v.iter().sum()).unwrap_or(0);
            let d = total.saturating_sub(self.last[i]);
            self.last[i] = total;
            any |= d > 0;
            out.insert((*name).into(), d.into());
        }
        any.then(|| serde_json::json!({ "ebpf_stats": out }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_templates() {
        let w = encode(&Template::of(Family::Windows)).unwrap();
        assert_eq!(&w.opts[..w.opt_len as usize], &[2, 4, 0, 0, 1, 3, 3, 0, 1, 1, 4, 2]);
        assert_eq!((w.mss_off, w.ws_off, w.ts_off), (2, 7, NONE));
        assert_eq!(w.window, 65535);
        let d = encode(&Template::of(Family::Android)).unwrap();
        assert_eq!((d.opt_len, d.window), (0, 65535));
        let a = encode(&Template::of(Family::Apple)).unwrap();
        assert_eq!(a.opt_len, 24);
        assert_eq!(&a.opts[..24], &[2, 4, 0, 0, 1, 3, 3, 0, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 0, 0]);
        assert_eq!((a.mss_off, a.ws_off, a.ts_off), (2, 7, 12));
        // Linux 模板与内核布局相同，不改选项
        assert_eq!(encode(&Template::of(Family::Linux)).unwrap().opt_len, 0);
        assert_eq!(std::mem::size_of::<Tpl>(), 48);
    }
}
