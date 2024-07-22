use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use byte_string::ByteStr;
use kcp::{Error as KcpError, KcpResult};
use log::{error, trace};
use tokio::{
    net::{ToSocketAddrs, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time,
};

use crate::{
    config::KcpConfig,
    control::{self, ControlSegment},
    session::{KcpSession, KcpSessionManager},
    skcp::KcpSocket,
    stream::KcpStream,
};

#[derive(Debug)]
pub struct KcpListener {
    udp: Arc<UdpSocket>,
    accept_rx: mpsc::Receiver<(KcpStream, SocketAddr)>,
    task_watcher: JoinHandle<()>,
    pub sessions: KcpSessionManager,
}

impl Drop for KcpListener {
    fn drop(&mut self) {
        self.task_watcher.abort();
    }
}

impl KcpListener {
    /// Create an `KcpListener` bound to `addr`
    pub async fn bind<A: ToSocketAddrs>(config: KcpConfig, addr: A) -> KcpResult<KcpListener> {
        let udp = UdpSocket::bind(addr).await?;
        KcpListener::from_socket(config, udp).await
    }

    /// Create a `KcpListener` from an existed `UdpSocket`
    pub async fn from_socket(config: KcpConfig, udp: UdpSocket) -> KcpResult<KcpListener> {
        let udp = Arc::new(udp);
        let server_udp = udp.clone();

        let (accept_tx, accept_rx) = mpsc::channel(1024 /* backlogs */);

        let sessions = KcpSessionManager::new();
        // KcpSessionManager has Arc internally
        let sessions_clone = sessions.clone();

        let task_watcher = tokio::spawn(async move {
            let (close_tx, mut close_rx) = mpsc::channel(64);

            let mut packet_buffer = [0u8; 65536];
            loop {
                tokio::select! {
                    peer_addr = close_rx.recv() => {
                        let peer_addr = peer_addr.expect("close_tx closed unexpectedly");
                        sessions_clone.remove(peer_addr);
                        trace!("session peer_addr: {} removed", peer_addr);
                    }

                    recv_res = server_udp.recv_from(&mut packet_buffer) => {
                        match recv_res {
                            Err(err) => {
                                error!("udp.recv_from failed, error: {}", err);
                                time::sleep(Duration::from_secs(1)).await;
                            }
                            Ok((n, peer_addr)) => {
                                let packet_buffer = &packet_buffer[..n];

                                if n == 20 {
                                    let control_segment = ControlSegment::decode(packet_buffer);
                                    match control_segment.cmd {
                                        0xff => {
                                            let conv = sessions_clone.alloc_conv();
                                            let token = rand::random();
                                            let socket = match KcpSocket::new(&config, conv, token, server_udp.clone(), peer_addr, config.stream){
                                                Ok(socket) => socket,
                                                Err(err) => {
                                                    error!("KcpSocket::new failed, error: {}", err);
                                                    continue;
                                                }
                                            };
                                            let session = KcpSession::new_shared(socket, config.session_expire, Some((close_tx.clone(), conv)));
                                            sessions_clone.insert(conv, session.clone());
                                            accept_tx.send((KcpStream::with_session(session), peer_addr)).await.unwrap();
                                            let response_packet = control::build_handshake_response(conv, token);
                                            if let Err(err) = server_udp.send_to(&response_packet, peer_addr).await {
                                                error!("udp.send_to failed, error: {}", err);
                                            }
                                        }
                                        0x194 => {
                                            let conv = control_segment.conv;
                                            let token = control_segment.token;
                                            let session = match sessions_clone.get(conv).await {
                                                Some(s) => s,
                                                None => {
                                                    error!("get session failed, peer: {}, conv: {}, token: {}", peer_addr, conv, token);
                                                    continue;
                                                }
                                            };
                                            if session.token() != token {
                                                error!("token not match, peer: {}, conv: {}, token: {}, session token: {}", peer_addr, conv, token, session.token());
                                                continue;
                                            }
                                            sessions_clone.remove(conv);
                                        }
                                        _ => {
                                            error!("invalid control segment cmd: {}", control_segment.cmd);
                                        }
                                    }
                                    continue;
                                }

                                if n < kcp::KCP_OVERHEAD {
                                    error!("packet too short, received {} bytes, but at least {} bytes",
                                            n,
                                            kcp::KCP_OVERHEAD);
                                    continue;
                                }

                                let conv = kcp::get_conv(packet_buffer);
                                let token = kcp::get_token(packet_buffer);

                                trace!("received peer: {}, conv: {}, token: {}, {:?}", peer_addr, conv, token, ByteStr::new(packet_buffer));

                                let session = match sessions_clone.get(conv).await {
                                    Some(s) => s,
                                    None => {
                                        error!("get session failed, peer: {}, conv: {}, token: {}", peer_addr, conv, token);

                                        let response_packet = control::build_disconnect_request(conv, token, 0);
                                        let _ = server_udp.send_to(&response_packet, peer_addr).await;
                                        continue;
                                    }
                                };

                                if session.input(packet_buffer).await.is_err() {
                                    trace!("[SESSION] KCP session is closing while listener tries to input");
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(KcpListener {
            udp,
            accept_rx,
            task_watcher,
            sessions,
        })
    }

    /// Accept a new connected `KcpStream`
    pub async fn accept(&mut self) -> KcpResult<(KcpStream, SocketAddr)> {
        match self.accept_rx.recv().await {
            Some(s) => Ok(s),
            None => Err(KcpError::IoError(io::Error::new(
                ErrorKind::Other,
                "accept channel closed unexpectedly",
            ))),
        }
    }

    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<KcpResult<(KcpStream, SocketAddr)>> {
        self.accept_rx.poll_recv(cx).map(|op_res| {
            op_res.ok_or_else(|| {
                KcpError::IoError(io::Error::new(ErrorKind::Other, "accept channel closed unexpectedly"))
            })
        })
    }

    /// Get the local address of the underlying socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for KcpListener {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.udp.as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for KcpListener {
    fn as_raw_socket(&self) -> std::os::windows::prelude::RawSocket {
        self.udp.as_raw_socket()
    }
}

#[cfg(test)]
mod test {
    use futures_util::future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::KcpListener;
    use crate::{config::KcpConfig, stream::KcpStream};

    #[tokio::test]
    async fn multi_echo() {
        let _ = env_logger::try_init();

        let config = KcpConfig::default();

        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();

                tokio::spawn(async move {
                    let mut buffer = [0u8; 8192];
                    while let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }

                        let data = &buffer[..n];
                        stream.write_all(data).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
        });

        let mut vfut = Vec::new();

        for _ in 0..100 {
            vfut.push(async move {
                let mut stream = KcpStream::connect(&config, server_addr).await.unwrap();

                for _ in 0..20 {
                    const SEND_BUFFER: &[u8] = b"HELLO WORLD";
                    stream.write_all(SEND_BUFFER).await.unwrap();
                    stream.flush().await.unwrap();

                    let mut buffer = [0u8; 1024];
                    let n = stream.recv(&mut buffer).await.unwrap();
                    assert_eq!(SEND_BUFFER, &buffer[..n]);
                }
            });
        }

        future::join_all(vfut).await;
    }
}
