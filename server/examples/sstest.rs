//! 本地测试客户端：sstest <server> <method> <password> <target> [payload]
//! 多用户时 password 写成 "服务端PSK:用户PSK"。读到 EOF，stdout 输出内容，stderr 输出字节数。
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let svr: std::net::SocketAddr = a[1].parse()?;
    let cfg = ServerConfig::new(svr, a[3].clone(), a[2].parse().map_err(|_| anyhow::anyhow!("method"))?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let target: Address = match a[4].parse::<std::net::SocketAddr>() {
        Ok(s) => Address::SocketAddress(s),
        Err(_) => {
            let (h, p) = a[4].rsplit_once(':').unwrap();
            Address::DomainNameAddress(h.into(), p.parse()?)
        }
    };
    // payload 以 @ 开头表示从文件读二进制，\r\n 转义可写在命令行里
    let payload: Vec<u8> = match a.get(5) {
        Some(p) if p.starts_with('@') => std::fs::read(&p[1..])?,
        Some(p) => p.replace("\\r", "\r").replace("\\n", "\n").into_bytes(),
        None => b"hello\n".to_vec(),
    };
    let ctx = Context::new_shared(ServerType::Local);
    let mut s = ProxyClientStream::connect(ctx, &cfg, target).await?;
    s.write_all(&payload).await?;
    // SSTEST_DISCARD=1：只计数不保存，用于吞吐测试（不限时）
    if std::env::var_os("SSTEST_DISCARD").is_some() {
        let t = std::time::Instant::now();
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0u64;
        loop {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        let secs = t.elapsed().as_secs_f64();
        eprintln!("[sstest] 收到 {total} 字节，{secs:.2} s，{:.0} Mbit/s", total as f64 * 8.0 / secs / 1e6);
        return Ok(());
    }
    // 读到 EOF（最多 10 秒），stdout 输出全部内容，stderr 输出总字节数
    let mut all = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), s.read_to_end(&mut all)).await;
    use std::io::Write;
    std::io::stdout().write_all(&all)?;
    eprintln!("[sstest] 收到 {} 字节", all.len());
    Ok(())
}
