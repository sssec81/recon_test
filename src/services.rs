use futures_util::future::join_all;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const DEFAULT_PORTS: &[u16] = &[80, 443, 8000, 8080, 8443];

pub async fn probe_port(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    let connect_fut = TcpStream::connect(&addr);
    match timeout(Duration::from_secs(2), connect_fut).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

pub async fn probe_open_ports(host: &str, ports: &[u16]) -> Vec<u16> {
    let futs = ports.iter().map(|&p| async move {
        if probe_port(host, p).await {
            Some(p)
        } else {
            None
        }
    });
    join_all(futs).await.into_iter().flatten().collect()
}
