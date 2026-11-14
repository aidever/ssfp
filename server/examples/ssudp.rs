//! UDP 测试客户端：ssudp <server> <method> <password> <target> <payload> [次数]
//! 发 N 个包（默认 3），打印每个回包；多用户时 password 写成 "服务端PSK:用户PSK"。
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::relay::Address;
use shadowsocks::relay::udprelay::ProxySocket;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;

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
    let payload = a[5].as_bytes();
    let count: u64 = a.get(6).map(|s| s.parse()).transpose()?.unwrap_or(3);
    let ctx = Context::new_shared(ServerType::Local);
    let s = ProxySocket::connect(ctx, &cfg).await?;
    let mut ctrl = UdpSocketControlData::default();
    ctrl.client_session_id = std::process::id() as u64 * 7919 + 1;
    let mut buf = vec![0u8; 65536];
    let mut got = 0;
    for i in 1..=count {
        ctrl.packet_id = i;
        s.send_with_ctrl(&target, &ctrl, payload).await?;
        match tokio::time::timeout(std::time::Duration::from_secs(3), s.recv_with_ctrl(&mut buf)).await {
            Ok(Ok((n, from, _, _))) => {
                got += 1;
                println!("#{i} 来自 {from}: {}", String::from_utf8_lossy(&buf[..n]));
            }
            Ok(Err(e)) => println!("#{i} 错误: {e}"),
            Err(_) => println!("#{i} 超时"),
        }
    }
    eprintln!("[ssudp] {got}/{count} 个回包");
    Ok(())
}
