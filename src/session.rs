use std::{
    fmt::{self, Debug},
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use byte_string::ByteStr;
use dashmap::DashMap;
use log::{error, trace};
use spin::Mutex as SpinMutex;
use tokio::{
    sync::{mpsc, Notify},
    time::{self, Instant},
};

use crate::skcp::KcpSocket;

pub struct KcpSession {
    socket: SpinMutex<KcpSocket>,
    closed: AtomicBool,
    session_expire: Duration,
    session_close_notifier: Option<(mpsc::Sender<u32>, u32)>,
    notifier: Notify,
}

impl Drop for KcpSession {
    fn drop(&mut self) {
        trace!(
            "[SESSION] KcpSession conv {} is dropping, closed? {}",
            self.socket.lock().conv(),
            self.closed.load(Ordering::Acquire),
        );
    }
}

impl Debug for KcpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpSession")
            .field("socket", self.socket.lock().deref())
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("session_expired", &self.session_expire)
            .field("session_close_notifier", &self.session_close_notifier)
            .field("notifier", &self.notifier)
            .finish()
    }
}

impl KcpSession {
    fn new(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<u32>, u32)>,
    ) -> KcpSession {
        KcpSession {
            socket: SpinMutex::new(socket),
            closed: AtomicBool::new(false),
            session_expire,
            session_close_notifier,
            notifier: Notify::new(),
        }
    }

    pub fn new_shared(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<u32>, u32)>,
    ) -> Arc<KcpSession> {
        let is_client = session_close_notifier.is_none();

        let session = Arc::new(KcpSession::new(socket, session_expire, session_close_notifier));

        // Per-session updater
        {
            let session = session.clone();
            tokio::spawn(async move {
                while !session.closed.load(Ordering::Relaxed) {
                    let next = {
                        let mut socket = session.socket.lock();

                        let is_closed = session.closed.load(Ordering::Acquire);
                        if is_closed && socket.can_close() {
                            trace!("[SESSION] KCP session closing");
                            break;
                        }

                        // server socket expires
                        if !is_client {
                            // If this is a server stream, close it automatically after a period of time
                            let last_update_time = socket.last_update_time();
                            let elapsed = last_update_time.elapsed();

                            if elapsed > session.session_expire {
                                if elapsed > session.session_expire * 2 {
                                    // Force close. Client may have already gone.
                                    trace!(
                                        "[SESSION] force close inactive session, conv: {}, last_update: {}s ago",
                                        socket.conv(),
                                        elapsed.as_secs()
                                    );
                                    break;
                                }

                                if !is_closed {
                                    trace!(
                                        "[SESSION] closing inactive session, conv: {}, last_update: {}s ago",
                                        socket.conv(),
                                        elapsed.as_secs()
                                    );
                                    session.closed.store(true, Ordering::Release);
                                }
                            }
                        }

                        // If window is full, flush it immediately
                        if socket.need_flush() {
                            let _ = socket.flush();
                        }

                        match socket.update() {
                            Ok(next_next) => Instant::from_std(next_next),
                            Err(err) => {
                                error!("[SESSION] KCP update failed, error: {}", err);
                                Instant::now() + Duration::from_millis(10)
                            }
                        }
                    };

                    tokio::select! {
                        _ = time::sleep_until(next) => {},
                        _ = session.notifier.notified() => {},
                    }
                }

                {
                    // Close the socket.
                    // Wake all pending tasks and let all send/recv return EOF

                    let mut socket = session.socket.lock();
                    socket.close();
                }

                if let Some((ref notifier, conv)) = session.session_close_notifier {
                    let _ = notifier.send(conv).await;
                }

                session.closed.store(true, Ordering::Release);

                trace!("[SESSION] KCP session closed");
            });
        }

        session
    }

    pub fn kcp_socket(&self) -> &SpinMutex<KcpSocket> {
        &self.socket
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify();
    }

    pub async fn input(&self, buf: &[u8]) -> Result<(), SessionClosedError> {
        // bytes received from listener socket
        let mut socket = self.socket.lock();
        match socket.input(&buf) {
            Ok(waked) => {
                // trace!("[SESSION] UDP input {} bytes from channel {:?}",
                //        input_buffer.len(), ByteStr::new(&input_buffer));
                trace!(
                    "[SESSION] UDP input {} bytes from channel, waked? {} sender/receiver",
                    buf.len(),
                    waked
                );
                Ok(())
            }
            Err(err) => {
                error!(
                    "[SESSION] UDP input {} bytes from channel failed, error: {}, input buffer {:?}",
                    buf.len(),
                    err,
                    ByteStr::new(&buf)
                );
                Err(SessionClosedError)
            }
        }
    }

    pub fn conv(&self) -> u32 {
        let socket = self.socket.lock();
        socket.conv()
    }

    pub fn token(&self) -> u32 {
        let socket = self.socket.lock();
        socket.token()
    }

    pub fn notify(&self) {
        self.notifier.notify_one();
    }
}

pub struct SessionClosedError;

#[derive(Debug)]
struct KcpSessionUniq(Arc<KcpSession>);

impl Drop for KcpSessionUniq {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Deref for KcpSessionUniq {
    type Target = KcpSession;

    fn deref(&self) -> &KcpSession {
        &self.0
    }
}

#[derive(Clone, Debug, Default)]
pub struct KcpSessionManager {
    sessions: Arc<DashMap<u32, KcpSessionUniq>>,
}

impl KcpSessionManager {
    pub fn new() -> KcpSessionManager {
        KcpSessionManager {
            sessions: Arc::new(DashMap::new()),
        }
    }

    #[inline]
    pub fn alloc_conv(&self) -> u32 {
        loop {
            let conv = rand::random();
            if !self.sessions.contains_key(&conv) {
                return conv;
            }
        }
    }

    pub fn remove(&self, conv: u32) {
        self.sessions.remove(&conv);
    }

    pub fn insert(&self, conv: u32, session: Arc<KcpSession>) {
        self.sessions.insert(conv, KcpSessionUniq(session));
    }

    pub async fn get(&self, conv: u32) -> Option<Arc<KcpSession>> {
        return Some(self.sessions.get(&conv)?.0.clone());
    }
}
