//! TCP transport implementation.
//!
//! Provides connection-oriented TCP transport for SIP messages.
//! TCP is used when SIP messages exceed MTU size or when reliable
//! transport is required.
//!
//! # Read/write lock separation (2026-07-09 fix)
//!
//! `TcpTransport`/`TcpSender`'s connection-management path no longer
//! shares one lock between reading and writing on a connection.
//! Previously, `read_loop` held a single `Mutex<TcpConnection>` for the
//! *entire* duration of a blocking `read_message()` call (which itself
//! loops internally awaiting more socket data). Once that loop was
//! idling between messages, the lock stayed held, so a concurrent
//! `TcpSender::send()`/`TcpTransport::send()` on the same connection
//! blocked forever waiting for a lock that would only be released by
//! more data arriving — data that, in a request/response/re-request
//! pattern (send, receive, send again on the same connection), doesn't
//! arrive until *after* that blocked send completes. Confirmed by
//! direct testing (a second message queued on an otherwise-idle
//! connection hung indefinitely) before being tracked down here.
//!
//! The fix: `TcpStream::into_split()` gives independent
//! `OwnedReadHalf`/`OwnedWriteHalf` handles. The read loop owns its
//! `OwnedReadHalf` and read buffer exclusively (no `Arc`/`Mutex` — only
//! that one task ever touches them), so a blocked read never holds any
//! lock. Writers (production `send()`/`send_to()`, and the read loop's
//! own CRLF keep-alive pong/ping replies) go through a per-connection
//! `Mutex<OwnedWriteHalf>` that's only ever held for the duration of a
//! `write_all` call — never across a blocking read.
//!
//! [`TcpConnection`] (bundling one un-split `TcpStream`) is kept as-is
//! below for the handful of tests that exercise low-level message
//! framing directly (`read_message`/`write_message` on a single
//! stream) — that framing logic is orthogonal to the concurrency fix
//! above and didn't need to change; the shared `find_header_end`/
//! `parse_content_length`/`try_parse_message_from_buf` helpers are used
//! by both `TcpConnection` and the new split-based read path so the
//! framing behavior stays identical either way.
//!
//! This also incidentally fixes a second, unrelated gap: there was no
//! way to read back the real local address of an outbound client
//! connection (`TcpTransport::local_addr()` returns the transport's
//! nominal bind address, which for `new_client()` is just whatever the
//! caller passed and is typically `:0`). [`TcpTransport::connection_local_addr`]
//! now exposes the actual OS-assigned local address of a specific
//! connection, captured once at `connect()`/accept time.
//!
//! A third addition (2026-07-09, same session): `connect()` can now
//! bind the outbound connection to a *specific* local port, not just
//! read one back after the fact. Pass a `new_client(SocketAddr)` with
//! a nonzero port and `connect()` uses `TcpSocket::bind`+`connect`
//! instead of plain `TcpStream::connect` — needed for protocols (TS
//! 33.203 IPsec's negotiated `port-c`, in particular) where the peer
//! is told in advance which local port to expect traffic from/to, so
//! an OS-assigned ephemeral port won't do. A `:0` port keeps the
//! original OS-assigned behavior.

use crate::core::Result;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, trace, warn};

use crate::transport::keepalive::{
    strip_leading_keepalives, KeepAliveConfig, KEEPALIVE_PING, KEEPALIVE_PONG,
};
use crate::transport::traits::{IncomingMessage, OutgoingMessage, TransportProtocol};

#[cfg(test)]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock, Mutex as StdMutex,
};

/// Maximum SIP message size over TCP.
pub const MAX_TCP_SIZE: usize = 65536;

/// Initial buffer size for reading.
const INITIAL_BUF_SIZE: usize = 4096;

// Forced-error flags use thread-id-keyed storage so parallel tests can each
// arm a forced error on their own thread without disturbing siblings. A flag
// is "armed" when its value equals the arming thread's `current_thread_id()`;
// only that thread will then consume it. Zero means "not set".
//
// FORCE_ACCEPT_ERROR has three variants — we use one flag per variant rather
// than packing variant + thread id together; cleaner and equally cheap.
#[cfg(test)]
static FORCE_ACCEPT_ERROR_V1: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_ACCEPT_ERROR_V2: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_ACCEPT_ERROR_V3: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_READ_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_WRITE_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_BIND_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_LOCAL_ADDR_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_SKIP_CONNECT_INSERT: LazyLock<StdMutex<Option<SocketAddr>>> =
    LazyLock::new(|| StdMutex::new(None));

#[cfg(test)]
fn force_accept_error_once() {
    FORCE_ACCEPT_ERROR_V1.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_accept_error_other_message_once() {
    FORCE_ACCEPT_ERROR_V2.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_accept_error_other_kind_once() {
    FORCE_ACCEPT_ERROR_V3.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_read_error_once() {
    FORCE_READ_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_write_error_once() {
    FORCE_WRITE_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_bind_error_once() {
    FORCE_BIND_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_local_addr_error_once() {
    FORCE_LOCAL_ADDR_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_skip_connect_insert_once(dest: SocketAddr) {
    let mut guard = FORCE_SKIP_CONNECT_INSERT.lock().unwrap();
    *guard = Some(dest);
}

#[cfg(test)]
fn take_skip_connect_insert_for(dest: SocketAddr) -> bool {
    let mut guard = FORCE_SKIP_CONNECT_INSERT.lock().unwrap();
    if guard.as_ref() == Some(&dest) {
        *guard = None;
        true
    } else {
        false
    }
}

#[cfg(test)]
fn try_take(flag: &AtomicU64) -> bool {
    let current = current_thread_id();
    flag.load(Ordering::SeqCst) == current
        && flag
            .compare_exchange(current, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
}

#[cfg(test)]
fn take_forced_accept_error() -> Option<std::io::Error> {
    if try_take(&FORCE_ACCEPT_ERROR_V1) {
        Some(std::io::Error::other("forced accept error"))
    } else if try_take(&FORCE_ACCEPT_ERROR_V2) {
        Some(std::io::Error::other("forced accept error other"))
    } else if try_take(&FORCE_ACCEPT_ERROR_V3) {
        Some(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "forced accept error",
        ))
    } else {
        None
    }
}

#[cfg(test)]
fn take_forced_error(flag: &AtomicU64, message: &str) -> Option<std::io::Error> {
    if try_take(flag) {
        Some(std::io::Error::other(message))
    } else {
        None
    }
}

#[cfg(test)]
fn current_thread_id() -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    normalize_thread_id(hasher.finish())
}

#[cfg(test)]
fn normalize_thread_id(id: u64) -> u64 {
    if id == 0 {
        1
    } else {
        id
    }
}

/// Try to parse a complete SIP message out of a framing buffer
/// (double-CRLF header end + `Content-Length` body). Shared by both
/// [`TcpConnection`] and the split-read-half production path so the
/// framing behavior is identical either way.
fn try_parse_message_from_buf(buf: &mut BytesMut) -> Option<Bytes> {
    let data = &buf[..];
    let header_end = find_header_end(data)?;

    let headers = &data[..header_end];
    let content_length = parse_content_length(headers);

    let total_length = header_end + content_length;
    if data.len() < total_length {
        // Haven't received complete body yet.
        return None;
    }

    Some(buf.split_to(total_length).freeze())
}

/// TCP connection state bundling one un-split stream. Used directly by
/// the low-level framing tests below; the production `TcpTransport`/
/// `TcpSender` connection-management path uses split read/write halves
/// instead (see this module's doc comment) and doesn't construct this
/// type.
#[cfg(test)]
struct TcpConnection {
    /// The TCP stream.
    stream: TcpStream,
    /// Remote address.
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// Read buffer.
    read_buf: BytesMut,
    /// When we last sent a CRLF keep-alive ping; `None` until the
    /// first one fires.
    last_ping_sent: Option<Instant>,
}

#[cfg(test)]
impl TcpConnection {
    fn new(stream: TcpStream, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            read_buf: BytesMut::with_capacity(INITIAL_BUF_SIZE),
            last_ping_sent: None,
        }
    }

    /// Read a complete SIP message from the connection.
    ///
    /// SIP over TCP uses Content-Length header for framing. CRLF
    /// keep-alive frames per RFC 5626 §3.5.1 are stripped from the
    /// stream and answered with a pong; if `keepalive.send_pings` is
    /// set, periodic outbound pings are emitted while waiting for data.
    async fn read_message(&mut self, keepalive: &KeepAliveConfig) -> Result<Option<Bytes>> {
        loop {
            // Strip any leading keep-alive frames already buffered and
            // reply with one pong per ping.
            let pings = strip_leading_keepalives(&mut self.read_buf);
            for _ in 0..pings {
                stream_write_all(&mut self.stream, KEEPALIVE_PONG).await?;
                trace!("Sent CRLF pong to {}", self.remote_addr);
            }

            // Try to parse a complete message from the buffer.
            if let Some(msg) = self.try_parse_message() {
                return Ok(Some(msg));
            }

            // Need more data. If keep-alive pings are enabled, race the
            // read against the ping deadline so the timer fires even
            // when the peer is silent.
            let mut temp_buf = [0u8; 4096];
            let read_result = if keepalive.send_pings {
                let last = self.last_ping_sent.unwrap_or_else(Instant::now);
                let elapsed = last.elapsed();
                let remaining = keepalive
                    .ping_interval
                    .checked_sub(elapsed)
                    .unwrap_or_default();
                tokio::time::timeout(remaining, stream_read(&mut self.stream, &mut temp_buf))
                    .await
                    .ok()
            } else {
                Some(stream_read(&mut self.stream, &mut temp_buf).await)
            };

            let n = match read_result {
                Some(Ok(n)) => n,
                Some(Err(e)) => return Err(e.into()),
                None => {
                    // Ping deadline elapsed — send `\r\n\r\n` and loop.
                    stream_write_all(&mut self.stream, KEEPALIVE_PING).await?;
                    self.last_ping_sent = Some(Instant::now());
                    trace!("Sent CRLF ping to {}", self.remote_addr);
                    continue;
                }
            };

            if n == 0 {
                // Connection closed
                if self.read_buf.is_empty() {
                    return Ok(None);
                }
                // Incomplete message
                return Ok(None);
            }

            self.read_buf.extend_from_slice(&temp_buf[..n]);

            // Limit buffer size
            if self.read_buf.len() > MAX_TCP_SIZE {
                return Err(crate::core::TransportError::MessageTooLarge {
                    size: self.read_buf.len(),
                    max: MAX_TCP_SIZE,
                }
                .into());
            }
        }
    }

    /// Try to parse a complete SIP message from the buffer.
    fn try_parse_message(&mut self) -> Option<Bytes> {
        try_parse_message_from_buf(&mut self.read_buf)
    }

    /// Write a message to the connection.
    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        stream_write_all(&mut self.stream, data).await?;
        Ok(())
    }
}

#[cfg(test)]
async fn stream_read(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_READ_ERROR, "forced read error") {
        return Err(err);
    }
    stream.read(buf).await
}

#[cfg(test)]
async fn stream_write_all(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_WRITE_ERROR, "forced write error") {
        return Err(err);
    }
    stream.write_all(data).await
}

/// `OwnedReadHalf` counterpart of [`stream_read`] — used by the
/// production split-read-half path. Shares the same forced-error test
/// hook so tests forcing a read error don't need to care which path
/// they're exercising.
async fn stream_read_half(half: &mut OwnedReadHalf, buf: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_READ_ERROR, "forced read error") {
        return Err(err);
    }
    half.read(buf).await
}

/// `OwnedWriteHalf` counterpart of [`stream_write_all`] — used by the
/// production split-read-half path (both for the writer's own sends
/// and the read loop's CRLF keep-alive pong/ping replies).
async fn stream_write_all_half(half: &mut OwnedWriteHalf, data: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_WRITE_ERROR, "forced write error") {
        return Err(err);
    }
    half.write_all(data).await
}

async fn bind_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_BIND_ERROR, "forced bind error") {
        return Err(err);
    }
    TcpListener::bind(addr).await
}

fn listener_local_addr(listener: &TcpListener) -> std::io::Result<SocketAddr> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_LOCAL_ADDR_ERROR, "forced local_addr error") {
        return Err(err);
    }
    listener.local_addr()
}

/// Find the end of SIP headers (double CRLF).
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Parse Content-Length from headers.
fn parse_content_length(headers: &[u8]) -> usize {
    let headers_str = match std::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    for line in headers_str.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("content-length:") || line_lower.starts_with("l:") {
            let value = line.split_once(':').map(|(_, value)| value).unwrap_or("");
            if let Ok(len) = value.trim().parse() {
                return len;
            }
        }
    }
    0
}

/// Per-connection state reachable for writing — shared between the
/// production writer path (`TcpTransport::send`/`TcpSender::send`) and
/// the read loop's own CRLF keep-alive pong/ping replies. Deliberately
/// does *not* hold the read half or read buffer: those are owned
/// exclusively by the read-loop task (see this module's doc comment).
struct ConnectionHandle {
    write_half: Mutex<OwnedWriteHalf>,
    /// The real local address of this specific connection, captured
    /// once at connect/accept time. See [`TcpTransport::connection_local_addr`].
    local_addr: SocketAddr,
}

/// State owned exclusively by one read-loop task: the read half and
/// its framing buffer. Never behind an `Arc`/`Mutex` — nothing else
/// ever touches it, which is precisely what lets a blocked read avoid
/// holding any lock.
struct ReadHalfState {
    read_half: OwnedReadHalf,
    remote_addr: SocketAddr,
    read_buf: BytesMut,
    last_ping_sent: Option<Instant>,
}

impl ReadHalfState {
    fn new(read_half: OwnedReadHalf, remote_addr: SocketAddr) -> Self {
        Self {
            read_half,
            remote_addr,
            read_buf: BytesMut::with_capacity(INITIAL_BUF_SIZE),
            last_ping_sent: None,
        }
    }

    fn try_parse_message(&mut self) -> Option<Bytes> {
        try_parse_message_from_buf(&mut self.read_buf)
    }

    /// Same framing/keep-alive behavior as [`TcpConnection::read_message`],
    /// but reading from an exclusively-owned `OwnedReadHalf` instead of
    /// a shared `TcpStream`. `conn` is used only for the brief pong/ping
    /// writes — never held while awaiting new data on `self.read_half`,
    /// which needs no lock at all. This is what fixes the deadlock: a
    /// concurrent write via `conn.write_half` can always acquire the
    /// lock immediately, since this read path only ever takes it for a
    /// `write_all` call that returns right away.
    async fn read_message(
        &mut self,
        keepalive: &KeepAliveConfig,
        conn: &ConnectionHandle,
    ) -> Result<Option<Bytes>> {
        loop {
            let pings = strip_leading_keepalives(&mut self.read_buf);
            for _ in 0..pings {
                let mut w = conn.write_half.lock().await;
                stream_write_all_half(&mut w, KEEPALIVE_PONG).await?;
                drop(w);
                trace!("Sent CRLF pong to {}", self.remote_addr);
            }

            if let Some(msg) = self.try_parse_message() {
                return Ok(Some(msg));
            }

            let mut temp_buf = [0u8; 4096];
            let read_result = if keepalive.send_pings {
                let last = self.last_ping_sent.unwrap_or_else(Instant::now);
                let elapsed = last.elapsed();
                let remaining = keepalive
                    .ping_interval
                    .checked_sub(elapsed)
                    .unwrap_or_default();
                tokio::time::timeout(
                    remaining,
                    stream_read_half(&mut self.read_half, &mut temp_buf),
                )
                .await
                .ok()
            } else {
                Some(stream_read_half(&mut self.read_half, &mut temp_buf).await)
            };

            let n = match read_result {
                Some(Ok(n)) => n,
                Some(Err(e)) => return Err(e.into()),
                None => {
                    let mut w = conn.write_half.lock().await;
                    stream_write_all_half(&mut w, KEEPALIVE_PING).await?;
                    drop(w);
                    self.last_ping_sent = Some(Instant::now());
                    trace!("Sent CRLF ping to {}", self.remote_addr);
                    continue;
                }
            };

            if n == 0 {
                return Ok(None);
            }

            self.read_buf.extend_from_slice(&temp_buf[..n]);

            if self.read_buf.len() > MAX_TCP_SIZE {
                return Err(crate::core::TransportError::MessageTooLarge {
                    size: self.read_buf.len(),
                    max: MAX_TCP_SIZE,
                }
                .into());
            }
        }
    }
}

/// TCP transport for SIP messages.
pub struct TcpTransport {
    /// Local address.
    local_addr: SocketAddr,
    /// The TCP listener (for server mode).
    listener: Option<TcpListener>,
    /// Active connections (keyed by remote address).
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionHandle>>>>,
    /// Read halves stashed by [`connect`](Self::connect) until
    /// [`start`](Self::start) claims them and spawns their read loops.
    /// Only needed for the "connect, then start" client pattern —
    /// accepted (server-side) connections spawn their read loop
    /// immediately inside the accept loop instead.
    pending_reads: Arc<Mutex<HashMap<SocketAddr, OwnedReadHalf>>>,
    /// Channel sender for incoming messages.
    incoming_tx: Option<mpsc::Sender<IncomingMessage>>,
    /// CRLF keep-alive configuration (RFC 5626 §3.5.1). Disabled by
    /// default to preserve existing behaviour; opt in via
    /// [`with_keepalive`](Self::with_keepalive).
    keepalive: KeepAliveConfig,
    /// Set only by [`new_client`](Self::new_client) when given a
    /// nonzero port — an explicit request that outbound connections
    /// bind to that specific local port. Deliberately *not* derived
    /// from `local_addr` directly: a [`bind`](Self::bind)-created
    /// transport also has a nonzero `local_addr` (its listener's real
    /// port), but that's an incidental fact about being a server, not
    /// a request to source outbound connections from that same port
    /// (which would just collide with the listener). Kept `None` for
    /// `bind()` and for `new_client(:0)`, in which case `connect()`
    /// falls back to the original OS-assigned-port behavior.
    explicit_connect_bind: Option<SocketAddr>,
}

impl TcpTransport {
    /// Bind to a local address and create a new TCP transport.
    ///
    /// This creates a listener for incoming connections.
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = bind_listener(addr).await?;
        let local_addr = listener_local_addr(&listener)?;
        debug!("TCP transport bound to {}", local_addr);

        Ok(Self {
            local_addr,
            listener: Some(listener),
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending_reads: Arc::new(Mutex::new(HashMap::new())),
            incoming_tx: None,
            keepalive: KeepAliveConfig::default(),
            explicit_connect_bind: None,
        })
    }

    /// Create a client-only TCP transport (no listener). If
    /// `local_addr` has a nonzero port, [`connect`](Self::connect)
    /// binds outbound connections to that specific port instead of
    /// letting the OS assign one — see
    /// [`explicit_connect_bind`](TcpTransport::explicit_connect_bind)'s
    /// doc comment for why this is `new_client`-only, not derived from
    /// `local_addr` generically.
    pub fn new_client(local_addr: SocketAddr) -> Self {
        let explicit_connect_bind = if local_addr.port() != 0 {
            Some(local_addr)
        } else {
            None
        };
        Self {
            local_addr,
            listener: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending_reads: Arc::new(Mutex::new(HashMap::new())),
            incoming_tx: None,
            keepalive: KeepAliveConfig::default(),
            explicit_connect_bind,
        }
    }

    /// Configure CRLF keep-alive (RFC 5626 §3.5.1) for this transport.
    ///
    /// Incoming pings (`\r\n\r\n`) are answered with a pong (`\r\n`)
    /// regardless of this setting. When [`KeepAliveConfig::send_pings`]
    /// is true, the read loop also emits outbound pings on each
    /// connection at the configured interval to keep NAT pinholes open.
    pub fn with_keepalive(mut self, keepalive: KeepAliveConfig) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Get the local address.
    ///
    /// For a transport created via [`bind`](Self::bind) this is the
    /// real bound address. For [`new_client`](Self::new_client) it's
    /// just whatever the caller passed in — typically `:0` — since a
    /// client-only transport has no listener to bind. Use
    /// [`connection_local_addr`](Self::connection_local_addr) for the
    /// real local address of a specific outbound connection instead.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the real local address of an established connection to
    /// `remote`, if one exists — captured once at connect/accept time
    /// from the underlying socket, unlike [`local_addr`](Self::local_addr)
    /// which is only accurate for [`bind`](Self::bind)-created
    /// transports.
    pub async fn connection_local_addr(&self, remote: SocketAddr) -> Option<SocketAddr> {
        let connections = self.connections.read().await;
        connections.get(&remote).map(|h| h.local_addr)
    }

    /// Connect to a remote address.
    ///
    /// If this transport was created via [`new_client`](Self::new_client)
    /// with a nonzero local port, the outbound connection is explicitly
    /// bound to it via `TcpSocket::bind`+`connect` — needed for schemes
    /// (like TS 33.203 IPsec's negotiated `port-c`) where the local
    /// port must be a specific, known value rather than an OS-assigned
    /// ephemeral one. Otherwise falls back to `TcpStream::connect`'s
    /// normal OS-assigned-port behavior.
    pub async fn connect(&self, addr: SocketAddr) -> Result<()> {
        // Check if already connected
        {
            let connections = self.connections.read().await;
            if connections.contains_key(&addr) {
                return Ok(());
            }
        }

        debug!("Connecting to {}", addr);
        let stream = if let Some(bind_addr) = self.explicit_connect_bind {
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            // SO_REUSEADDR allows rebinding the same local port
            // immediately after the previous connection is closed,
            // avoiding EADDRINUSE from TIME_WAIT state. Needed for
            // protocols (IMS TS 33.203) where the UE must reuse its
            // negotiated port-c for every protected REGISTER.
            socket.set_reuseaddr(true)?;
            socket.bind(bind_addr)?;
            socket.connect(addr).await?
        } else {
            TcpStream::connect(addr).await?
        };
        let local_addr = stream.local_addr()?;
        let (read_half, write_half) = stream.into_split();

        let mut connections = self.connections.write().await;
        #[cfg(test)]
        if take_skip_connect_insert_for(addr) {
            return Ok(());
        }
        connections.insert(
            addr,
            Arc::new(ConnectionHandle {
                write_half: Mutex::new(write_half),
                local_addr,
            }),
        );
        drop(connections);

        let mut pending = self.pending_reads.lock().await;
        pending.insert(addr, read_half);

        Ok(())
    }

    /// Send a message to a destination.
    ///
    /// Connects if not already connected.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        let dest = msg.destination;

        // Ensure connection exists
        self.connect(dest).await?;

        // Get connection and send
        let conn = {
            let connections = self.connections.read().await;
            connections.get(&dest).cloned()
        }
        .ok_or(crate::core::TransportError::ConnectionClosed)?;

        let mut w = conn.write_half.lock().await;
        trace!("Sending {} bytes to {} over TCP", msg.data.len(), dest);
        stream_write_all_half(&mut w, &msg.data).await?;

        Ok(())
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        self.send(OutgoingMessage::new(Bytes::copy_from_slice(data), dest))
            .await
    }

    /// Start the transport, accepting connections and receiving messages.
    ///
    /// Returns a receiver for incoming messages.
    pub fn start(mut self) -> (mpsc::Receiver<IncomingMessage>, TcpSender) {
        let (tx, rx) = mpsc::channel(256);
        self.incoming_tx = Some(tx.clone());

        let connections = self.connections.clone();
        let listener = self.listener.take();
        let keepalive = self.keepalive.clone();
        let pending_reads = self.pending_reads.clone();

        // Spawn accept loop if we have a listener
        if let Some(listener) = listener {
            let tx_clone = tx.clone();
            let connections_clone = connections.clone();
            let keepalive_clone = keepalive.clone();

            tokio::spawn(async move {
                loop {
                    let accept_result = async {
                        #[cfg(test)]
                        {
                            if let Some(err) = take_forced_accept_error() {
                                return Err(err);
                            }
                        }
                        listener.accept().await
                    }
                    .await;

                    match accept_result {
                        Ok((stream, remote_addr)) => {
                            debug!("Accepted connection from {}", remote_addr);

                            let local_addr = match stream.local_addr() {
                                Ok(a) => a,
                                Err(e) => {
                                    error!(
                                        "failed to read local_addr for accepted connection from {}: {}",
                                        remote_addr, e
                                    );
                                    continue;
                                }
                            };
                            let (read_half, write_half) = stream.into_split();
                            let handle = Arc::new(ConnectionHandle {
                                write_half: Mutex::new(write_half),
                                local_addr,
                            });

                            // Store connection
                            {
                                let mut conns = connections_clone.write().await;
                                conns.insert(remote_addr, handle.clone());
                            }

                            // Spawn read loop for this connection
                            let read_state = ReadHalfState::new(read_half, remote_addr);
                            let tx = tx_clone.clone();
                            let conns = connections_clone.clone();
                            let ka = keepalive_clone.clone();
                            tokio::spawn(async move {
                                Self::read_loop(read_state, handle, tx, conns, ka).await;
                            });
                        }
                        Err(e) => {
                            error!("TCP accept error: {}", e);
                            #[cfg(test)]
                            if e.kind() == std::io::ErrorKind::Other
                                && e.to_string() == "forced accept error"
                            {
                                break;
                            }
                        }
                    }
                }
            });
        }

        // Start read loops for existing (pre-`connect()`ed) connections.
        let tx_clone = tx;
        let connections_clone = connections.clone();
        let keepalive_existing = keepalive;
        tokio::spawn(async move {
            let addrs: Vec<SocketAddr> = {
                let pending = pending_reads.lock().await;
                pending.keys().copied().collect()
            };
            for addr in addrs {
                let read_half = {
                    let mut pending = pending_reads.lock().await;
                    pending.remove(&addr)
                };
                let Some(read_half) = read_half else { continue };
                let handle = {
                    let conns = connections_clone.read().await;
                    conns.get(&addr).cloned()
                };
                let Some(handle) = handle else { continue };

                let read_state = ReadHalfState::new(read_half, addr);
                let tx = tx_clone.clone();
                let conns = connections_clone.clone();
                let ka = keepalive_existing.clone();
                tokio::spawn(async move {
                    Self::read_loop(read_state, handle, tx, conns, ka).await;
                });
            }
        });

        let sender = TcpSender {
            connections: self.connections.clone(),
        };

        (rx, sender)
    }

    /// Read loop for a single connection.
    async fn read_loop(
        mut read_state: ReadHalfState,
        handle: Arc<ConnectionHandle>,
        tx: mpsc::Sender<IncomingMessage>,
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionHandle>>>>,
        keepalive: KeepAliveConfig,
    ) {
        let remote_addr = read_state.remote_addr;
        loop {
            let result = read_state.read_message(&keepalive, &handle).await;

            match result {
                Ok(Some(data)) => {
                    trace!(
                        "Received {} bytes from {} over TCP",
                        data.len(),
                        remote_addr
                    );
                    let msg = IncomingMessage {
                        data,
                        source: remote_addr,
                        transport: TransportProtocol::Tcp,
                    };

                    if tx.send(msg).await.is_err() {
                        debug!("Receiver dropped, stopping TCP read loop");
                        break;
                    }
                }
                Ok(None) => {
                    debug!("Connection closed by {}", remote_addr);
                    break;
                }
                Err(e) => {
                    warn!("TCP read error from {}: {}", remote_addr, e);
                    break;
                }
            }
        }

        // Remove connection
        let mut conns = connections.write().await;
        conns.remove(&remote_addr);
        debug!("Removed connection to {}", remote_addr);
    }

    /// Get a sender handle.
    pub fn sender(&self) -> TcpSender {
        TcpSender {
            connections: self.connections.clone(),
        }
    }
}

/// Cloneable sender for TCP transport.
#[derive(Clone)]
pub struct TcpSender {
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionHandle>>>>,
}

impl TcpSender {
    /// Send a message.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        let dest = msg.destination;

        let conn = {
            let connections = self.connections.read().await;
            connections.get(&dest).cloned()
        };

        if let Some(conn) = conn {
            let mut w = conn.write_half.lock().await;
            trace!("Sending {} bytes to {} over TCP", msg.data.len(), dest);
            stream_write_all_half(&mut w, &msg.data).await?;
            Ok(())
        } else {
            Err(crate::core::TransportError::ConnectionClosed.into())
        }
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        self.send(OutgoingMessage::new(Bytes::copy_from_slice(data), dest))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Once};

    fn init_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_test_writer()
                .try_init();
        });
    }

    async fn wait_for_forced_accept_error_clear_inner(flag: &AtomicU64) {
        for _ in 0..20 {
            if flag.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("forced accept error not consumed");
    }

    async fn wait_for_forced_accept_error_v1_clear() {
        wait_for_forced_accept_error_clear_inner(&FORCE_ACCEPT_ERROR_V1).await;
    }

    async fn wait_for_forced_accept_error_v2_clear() {
        wait_for_forced_accept_error_clear_inner(&FORCE_ACCEPT_ERROR_V2).await;
    }

    async fn wait_for_forced_accept_error_v3_clear() {
        wait_for_forced_accept_error_clear_inner(&FORCE_ACCEPT_ERROR_V3).await;
    }

    // Constants tests
    #[test]
    fn test_max_tcp_size() {
        assert_eq!(MAX_TCP_SIZE, 65536);
    }

    #[test]
    fn test_initial_buf_size() {
        assert_eq!(INITIAL_BUF_SIZE, 4096);
    }

    // find_header_end tests
    #[test]
    fn test_find_header_end() {
        let data = b"INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_header_end(data), Some(46));

        let data = b"INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_empty() {
        let data = b"";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_only_crlf() {
        let data = b"\r\n\r\n";
        assert_eq!(find_header_end(data), Some(4));
    }

    #[test]
    fn test_find_header_end_partial_crlf() {
        let data = b"\r\n\r";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_multiple_crlf() {
        // First occurrence at position 4
        let data = b"\r\n\r\nmore data\r\n\r\n";
        assert_eq!(find_header_end(data), Some(4));
    }

    #[test]
    fn test_find_header_end_short_data() {
        let data = b"abc";
        assert_eq!(find_header_end(data), None);
    }

    // parse_content_length tests
    #[test]
    fn test_parse_content_length() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: 123\r\n\r\n";
        assert_eq!(parse_content_length(headers), 123);

        let headers = b"INVITE sip:test SIP/2.0\r\nl: 456\r\n\r\n";
        assert_eq!(parse_content_length(headers), 456);

        let headers = b"INVITE sip:test SIP/2.0\r\n\r\n";
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_with_spaces() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length:   789   \r\n\r\n";
        assert_eq!(parse_content_length(headers), 789);
    }

    #[test]
    fn test_parse_content_length_uppercase() {
        let headers = b"INVITE sip:test SIP/2.0\r\nCONTENT-LENGTH: 100\r\n\r\n";
        assert_eq!(parse_content_length(headers), 100);
    }

    #[test]
    fn test_parse_content_length_mixed_case() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-length: 200\r\n\r\n";
        assert_eq!(parse_content_length(headers), 200);
    }

    #[test]
    fn test_parse_content_length_short_form_uppercase() {
        let headers = b"INVITE sip:test SIP/2.0\r\nL: 300\r\n\r\n";
        assert_eq!(parse_content_length(headers), 300);
    }

    #[test]
    fn test_parse_content_length_invalid_value() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: invalid\r\n\r\n";
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_empty() {
        let headers = b"";
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_invalid_utf8() {
        let headers = &[0xFF, 0xFE, 0x00, 0x01];
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_multiple_headers() {
        // Content-Length appears in multiple headers, should return first one
        let headers =
            b"INVITE sip:test SIP/2.0\r\nContent-Length: 100\r\nContent-Length: 200\r\n\r\n";
        assert_eq!(parse_content_length(headers), 100);
    }

    #[test]
    fn test_parse_content_length_no_colon_value() {
        // Missing value after colon
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length:\r\n\r\n";
        assert_eq!(parse_content_length(headers), 0);
    }

    // TcpTransport tests
    #[tokio::test]
    async fn test_tcp_bind() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        assert_ne!(transport.local_addr().port(), 0);
    }

    #[tokio::test]
    async fn test_tcp_bind_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        assert!(transport.local_addr().is_ipv6());
    }

    #[tokio::test]
    async fn test_tcp_bind_forced_error() {
        force_bind_error_once();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let result = TcpTransport::bind(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_bind_forced_local_addr_error() {
        force_local_addr_error_once();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let result = TcpTransport::bind(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_connection_read_and_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(server_addr).await.unwrap();
            let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(msg).await.unwrap();

            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let (stream, remote) = listener.accept().await.unwrap();
        let mut conn = TcpConnection::new(stream, remote);
        let msg = conn
            .read_message(&KeepAliveConfig::default())
            .await
            .unwrap()
            .unwrap();
        assert!(msg.starts_with(b"INVITE"));

        conn.write_message(b"PONG").await.unwrap();
        let received = client_task.await.unwrap();
        assert!(received.contains("PONG"));
    }

    #[tokio::test]
    async fn test_tcp_connection_forced_read_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let client_task =
            tokio::spawn(async move { TcpStream::connect(server_addr).await.unwrap() });

        let (stream, remote) = listener.accept().await.unwrap();
        let mut conn = TcpConnection::new(stream, remote);
        let _client = client_task.await.unwrap();

        force_read_error_once();
        let result = conn.read_message(&KeepAliveConfig::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_connection_forced_write_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let _stream = TcpStream::connect(server_addr).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let (stream, remote) = listener.accept().await.unwrap();
        let mut conn = TcpConnection::new(stream, remote);

        force_write_error_once();
        let result = conn.write_message(b"PING").await;
        assert!(result.is_err());

        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_sender_send_existing_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(server_addr).await.unwrap();
            let mut buf = [0u8; 16];
            let n =
                tokio::time::timeout(std::time::Duration::from_millis(500), client.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            buf[..n].to_vec()
        });

        let (stream, remote_addr) = listener.accept().await.unwrap();
        let local_addr = stream.local_addr().unwrap();
        let (_read_half, write_half) = stream.into_split();
        let mut map = HashMap::new();
        map.insert(
            remote_addr,
            Arc::new(ConnectionHandle {
                write_half: Mutex::new(write_half),
                local_addr,
            }),
        );
        let sender = TcpSender {
            connections: Arc::new(RwLock::new(map)),
        };

        let msg = OutgoingMessage::new(Bytes::from_static(b"PING"), remote_addr);
        sender.send(msg).await.unwrap();

        let data = client_task.await.unwrap();
        assert_eq!(data, b"PING");
    }

    #[tokio::test]
    async fn test_tcp_accept_error_logged() {
        init_tracing();
        force_accept_error_once();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();

        let (_rx, _sender) = server.start();
        wait_for_forced_accept_error_v1_clear().await;
    }

    #[tokio::test]
    async fn test_tcp_accept_error_other_message() {
        init_tracing();
        force_accept_error_other_message_once();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();

        let (_rx, _sender) = server.start();
        wait_for_forced_accept_error_v2_clear().await;
    }

    #[tokio::test]
    async fn test_tcp_accept_error_other_kind() {
        init_tracing();
        force_accept_error_other_kind_once();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();

        let (_rx, _sender) = server.start();
        wait_for_forced_accept_error_v3_clear().await;
    }

    #[tokio::test]
    async fn test_wait_for_forced_accept_error_clear_panics() {
        let flag = Arc::new(AtomicU64::new(1));
        let flag_handle = flag.clone();
        let handle = tokio::spawn(async move {
            wait_for_forced_accept_error_clear_inner(&flag_handle).await;
        });
        let result = handle.await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_start_spawns_read_loop_for_existing_connections() {
        init_tracing();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let msg = b"OPTIONS sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(msg).await.unwrap();
        });

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::new_client(client_addr);
        transport.connect(server_addr).await.unwrap();

        let (mut rx, _sender) = transport.start();

        let received = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.transport, TransportProtocol::Tcp);

        let _ = server_task.await;
    }

    #[test]
    fn test_tcp_new_client() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let transport = TcpTransport::new_client(addr);
        assert_eq!(transport.local_addr(), addr);
        assert!(transport.listener.is_none());
    }

    #[tokio::test]
    async fn test_tcp_local_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let local = transport.local_addr();
        assert!(local.port() > 0);
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_tcp_sender() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let _sender = transport.sender();
        // Sender created successfully
    }

    #[tokio::test]
    async fn test_tcp_sender_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let sender1 = transport.sender();
        let _sender2 = sender1.clone();
        // Cloned successfully
    }

    #[tokio::test]
    async fn test_tcp_sender_no_connection() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let sender = transport.sender();

        // Try to send without connection - should fail
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), dest);
        let result = sender.send(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_send_missing_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        force_skip_connect_insert_once(server_addr);
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), server_addr);
        let result = client.send(msg).await;
        assert!(result.is_err());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_tcp_send_forced_write_error() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();
        let (_rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        client.connect(server_addr).await.unwrap();

        force_write_error_once();
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), server_addr);
        let result = client.send(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_sender_forced_write_error() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();
        let (_rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        client.connect(server_addr).await.unwrap();

        let sender = client.sender();
        force_write_error_once();
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), server_addr);
        let result = sender.send(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_connect_and_send() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client and connect
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send a message
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        client.send_to(msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
        assert_eq!(received.transport, TransportProtocol::Tcp);
    }

    #[tokio::test]
    async fn test_tcp_connect_already_connected() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (_rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Connect twice - second should succeed (noop)
        client.connect(server_addr).await.unwrap();
        client.connect(server_addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_send_with_body() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send a message with a body
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 11\r\n\r\nHello World";
        client.send_to(msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_send_multiple_messages() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send multiple messages
        for i in 0..3 {
            let msg = format!("MESSAGE sip:test{} SIP/2.0\r\nContent-Length: 0\r\n\r\n", i);
            client.send_to(msg.as_bytes(), server_addr).await.unwrap();
        }

        // Receive all
        for _ in 0..3 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(received.data.starts_with(b"MESSAGE"));
        }
    }

    #[tokio::test]
    async fn test_tcp_connect_fail() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Try to connect to a port with no listener
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let result = client.connect(bad_addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_start_client_only() {
        // Create client-only transport
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let transport = TcpTransport::new_client(addr);

        // Start should work even without listener
        let (_rx, _sender) = transport.start();
    }

    #[tokio::test]
    async fn test_tcp_bidirectional() {
        init_tracing();
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut server_rx, _server_sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        let (_client_rx, _client_sender) = client.start();

        // Client sends to server
        let client_transport =
            TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
        client_transport
            .send_to(b"PING\r\n\r\n", server_addr)
            .await
            .unwrap();

        // Server receives
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), server_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received.data[..], b"PING\r\n\r\n");

        // Server responds via its sender
        // Note: In real usage, we'd need to respond to the client's address from received.source
    }

    // TcpConnection tests
    #[tokio::test]
    async fn test_tcp_connection_new() {
        // Create a listener to get a stream
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect in background
        let connect_handle = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        // Accept connection
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let conn = TcpConnection::new(stream, remote_addr);

        assert_eq!(conn.remote_addr, remote_addr);
        assert!(conn.read_buf.is_empty());

        connect_handle.await.unwrap();
    }

    // OutgoingMessage tests
    #[test]
    fn test_outgoing_message_new() {
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), dest);
        assert_eq!(msg.destination, dest);
        assert_eq!(&msg.data[..], b"test");
    }

    // Additional comprehensive tests for 98%+ coverage

    // Message framing edge cases
    #[tokio::test]
    async fn test_tcp_message_too_large() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection (bypass transport layer)
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send a message with headers indicating it exceeds MAX_TCP_SIZE
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            MAX_TCP_SIZE + 1
        );
        stream.write_all(headers.as_bytes()).await.unwrap();

        // Send enough data to trigger the buffer limit check
        let chunk = vec![b'X'; 4096];
        for _ in 0..(MAX_TCP_SIZE / 4096 + 2) {
            stream.write_all(&chunk).await.unwrap();
        }

        // Server should close connection due to message too large
        // The receiver should not get a valid message or should timeout
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        // Timeout indicates no valid message arrived
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_partial_message_on_close() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send incomplete message (headers without complete double CRLF)
        stream
            .write_all(b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 10\r\n")
            .await
            .unwrap();

        // Close connection without completing the message
        drop(stream);

        // Server should handle this gracefully (return None on incomplete message)
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        // Should timeout as incomplete messages are discarded
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_multiple_messages_in_buffer() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send multiple messages in one write (TCP coalescing simulation)
        let msg1 = b"INVITE sip:test1@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg2 = b"INVITE sip:test2@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg3 = b"INVITE sip:test3@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        let mut combined = Vec::new();
        combined.extend_from_slice(msg1);
        combined.extend_from_slice(msg2);
        combined.extend_from_slice(msg3);

        stream.write_all(&combined).await.unwrap();
        stream.flush().await.unwrap();

        // Should receive all three messages separately
        for i in 1..=3 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let expected = format!("test{}@example.com", i);
            assert!(String::from_utf8_lossy(&received.data).contains(&expected));
        }
    }

    #[tokio::test]
    async fn test_tcp_message_with_large_body() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send a message with a large body (but under MAX_TCP_SIZE)
        let body = vec![b'X'; 10000];
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(&body);

        client.send_to(&msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.data.len(), msg.len());
        assert_eq!(&received.data[..], &msg[..]);
    }

    #[tokio::test]
    async fn test_tcp_incremental_message_assembly() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send message in small chunks to test incremental assembly
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nHELLO";

        for chunk in msg.chunks(5) {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Should receive complete message
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_message_with_partial_body() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send headers indicating body of 100 bytes
        stream
            .write_all(b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 100\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send only 50 bytes of body
        stream.write_all(&[b'A'; 50]).await.unwrap();
        stream.flush().await.unwrap();

        // Should not receive message yet (incomplete)
        let result = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(result.is_err());

        // Now send remaining 50 bytes
        stream.write_all(&[b'B'; 50]).await.unwrap();
        stream.flush().await.unwrap();

        // Should now receive complete message
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Headers: "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 100\r\n\r\n" = 60 bytes
        assert_eq!(received.data.len(), 60 + 100); // headers + body
    }

    #[tokio::test]
    async fn test_tcp_sender_send_to() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client with connection
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Establish connection
        client.connect(server_addr).await.unwrap();

        // Get sender and use send_to
        let sender = client.sender();
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        sender.send_to(msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_connection_close_cleanup() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (_rx, _sender) = server.start();

        // Create and connect client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        client.connect(server_addr).await.unwrap();

        // Verify connection exists
        {
            let connections = client.connections.read().await;
            assert_eq!(connections.len(), 1);
        }

        // Close connection by dropping client
        drop(client);

        // Give time for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connection should be cleaned up (we can't directly verify the server's
        // connection map since it's private, but the test exercises the cleanup path)
    }

    #[tokio::test]
    async fn test_tcp_receiver_dropped() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Connect
        client.connect(server_addr).await.unwrap();

        // Drop receiver to simulate receiver being closed
        drop(rx);

        // Send a message - read loop should detect dropped receiver and exit
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let result = client.send_to(msg, server_addr).await;
        assert!(result.is_ok()); // Send succeeds, but read loop will stop

        // Give time for read loop to detect dropped receiver
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_tcp_connection_read_write_errors() {
        // Test connection to invalid address (should fail)
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Try to send to non-existent server
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let result = client.send_to(msg, bad_addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_empty_message_after_headers() {
        // Test message with Content-Length: 0
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send message with no body
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        client.send_to(msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_connection_graceful_close() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let stream = TcpStream::connect(server_addr).await.unwrap();

        // Close connection immediately (graceful close)
        drop(stream);

        // Server should handle this gracefully
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        // Should timeout with no message
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_message_spanning_multiple_reads() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send a message that will span multiple read operations
        let body = vec![b'X'; 8192]; // Larger than single read buffer
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(&body);

        // Send in chunks smaller than the message
        for chunk in msg.chunks(1024) {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // Should receive complete message
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.data.len(), msg.len());
    }

    #[tokio::test]
    async fn test_tcp_compact_header_form() {
        // Test with compact form "l:" instead of "Content-Length:"
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send message with compact header form
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nl: 5\r\n\r\nHELLO";
        client.send_to(msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_no_content_length_header() {
        // Test message without Content-Length (should assume 0)
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send message without Content-Length header
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nVia: SIP/2.0/TCP test\r\n\r\n";
        client.send_to(msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[test]
    fn test_parse_content_length_negative() {
        // Test parsing negative content length (should return 0 on parse error)
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: -100\r\n\r\n";
        // Negative numbers will fail usize parsing, returning 0
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_overflow() {
        // Test parsing extremely large number
        let headers =
            b"INVITE sip:test SIP/2.0\r\nContent-Length: 999999999999999999999999\r\n\r\n";
        // Overflow will fail parsing, returning 0
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_find_header_end_exact_boundary() {
        // Test when data is exactly 3 bytes (boundary case for saturating_sub)
        let data = b"abc";
        assert_eq!(find_header_end(data), None);

        let data = b"ab";
        assert_eq!(find_header_end(data), None);

        let data = b"a";
        assert_eq!(find_header_end(data), None);
    }

    #[tokio::test]
    async fn test_tcp_send_after_connection_established() {
        // Test send() method specifically (not send_to)
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Use OutgoingMessage directly
        let data =
            Bytes::from_static(b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");
        let msg = OutgoingMessage::new(data.clone(), server_addr);

        client.send(msg).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], &data[..]);
    }

    #[tokio::test]
    async fn test_tcp_headers_with_multiple_colons() {
        // Test header parsing with URLs containing colons
        let headers = b"INVITE sip:test@example.com:5060 SIP/2.0\r\nContent-Length: 10\r\n\r\n";
        assert_eq!(parse_content_length(headers), 10);
    }

    #[tokio::test]
    async fn test_tcp_connection_buffer_initialization() {
        // Test that TcpConnection initializes with correct buffer capacity
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_handle = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        let (stream, remote_addr) = listener.accept().await.unwrap();
        let conn = TcpConnection::new(stream, remote_addr);

        assert_eq!(conn.read_buf.capacity(), INITIAL_BUF_SIZE);
        assert_eq!(conn.read_buf.len(), 0);

        connect_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_start_with_existing_connections() {
        // Test starting transport with pre-existing connections (covers lines 292-297)
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut server_rx, _server_sender) = server.start();

        // Create client and establish connection BEFORE starting
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Connect before starting (this creates an existing connection)
        client.connect(server_addr).await.unwrap();

        // Verify connection exists
        {
            let connections = client.connections.read().await;
            assert_eq!(connections.len(), 1);
        }

        // Now start the client transport with existing connection
        let (_client_rx, _client_sender) = client.start();

        // The existing connection should be able to send messages
        let new_client = TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        new_client.send_to(msg, server_addr).await.unwrap();

        // Server should receive it
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), server_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_write_error_on_closed_connection() {
        // Test write errors when connection is closed
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (rx, _sender) = server.start();

        // Create client and connect
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        client.connect(server_addr).await.unwrap();

        // Close server receiver and sender to cause connection to be reset
        drop(rx);
        drop(_sender);

        // Give time for connection to close
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Try to send - should eventually fail
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        // First send might succeed (data buffered), but connection will close
        let _ = client.send_to(msg, server_addr).await;

        // Wait for connection to fully close
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn test_tcp_multiple_clients_to_server() {
        // Test server handling multiple client connections
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create multiple clients
        let client1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client1 = TcpTransport::bind(client1_addr).await.unwrap();

        let client2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client2 = TcpTransport::bind(client2_addr).await.unwrap();

        // Both clients send messages
        let msg1 = b"INVITE sip:client1@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg2 = b"INVITE sip:client2@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        client1.send_to(msg1, server_addr).await.unwrap();
        client2.send_to(msg2, server_addr).await.unwrap();

        // Server should receive both messages
        let mut received_count = 0;
        for _ in 0..2 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();

            let is_client1 = received.data.windows(7).any(|w| w == b"client1");
            let is_client2 = received.data.windows(7).any(|w| w == b"client2");
            received_count += usize::from(is_client1) + usize::from(is_client2);
        }

        assert_eq!(received_count, 2);
    }

    #[tokio::test]
    async fn test_tcp_message_exactly_at_buffer_boundary() {
        // Test message that exactly fills read buffer
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Create message with body size that, with headers, is close to buffer size
        let body_size = 4000; // Close to INITIAL_BUF_SIZE
        let body = vec![b'X'; body_size];
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            body_size
        );
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(&body);

        client.send_to(&msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.data.len(), msg.len());
    }

    #[tokio::test]
    async fn test_tcp_connection_state_after_multiple_messages() {
        // Test that connection state is correct after multiple messages
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send several messages with different sizes
        let messages = vec![
            b"INVITE sip:test1@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"INVITE sip:test2@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nHELLO".to_vec(),
            b"INVITE sip:test3@example.com SIP/2.0\r\nContent-Length: 10\r\n\r\nHELLOWORLD"
                .to_vec(),
        ];

        for msg in &messages {
            client.send_to(msg, server_addr).await.unwrap();
        }

        // Receive all messages
        for _ in 0..messages.len() {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(!received.data.is_empty());
        }
    }

    #[tokio::test]
    async fn test_keepalive_ping_replied_with_pong() {
        // Send a CRLF-CRLF ping straight at our read loop and verify
        // we get a CRLF pong back without the ping being surfaced as a
        // SIP message.
        let server = TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let server_addr = server.local_addr();
        let (mut rx, _sender) = server.start();

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(b"\r\n\r\n").await.unwrap();

        // Read the pong (one CRLF).
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\r\n", "expected CRLF pong");

        // Follow up with a real SIP message to confirm the connection
        // is still parsing correctly after the keep-alive exchange.
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        client.write_all(msg).await.unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_keepalive_outbound_ping_emitted() {
        // With send_pings enabled and a tiny interval, the server's
        // read loop should emit a CRLF-CRLF ping to the client even
        // when the client never sends anything.
        let server = TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap()
            .with_keepalive(KeepAliveConfig::enabled_with_interval(
                std::time::Duration::from_millis(50),
            ));
        let server_addr = server.local_addr();
        let (_rx, _sender) = server.start();

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\r\n\r\n", "expected CRLF-CRLF ping");
    }

    #[tokio::test]
    async fn test_keepalive_leading_crlfs_before_message_are_consumed() {
        // A real SIP request prefixed by stray CRLF/CRLF-CRLF runs
        // (e.g. from a peer that pinged us mid-burst) must still parse
        // cleanly per RFC 3261 §7.5.
        let server = TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let server_addr = server.local_addr();
        let (mut rx, _sender) = server.start();

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        // Two pings (CRLFCRLF + CRLFCRLF) followed by a real INVITE.
        let payload =
            b"\r\n\r\n\r\n\r\nINVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        client.write_all(payload).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(received.data.starts_with(b"INVITE"));
        // We should also receive two pongs back.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        // Two pongs may arrive coalesced as `\r\n\r\n` or split.
        assert!(n >= 2, "expected at least one CRLF pong, got {} bytes", n);
        assert!(&buf[..n].starts_with(b"\r\n"));
    }

    // --- Regression test for the 2026-07-09 read/write lock-separation fix ---

    /// Reproduces the original bug directly: send a message on a
    /// connection, receive its response, then send a *second* message
    /// on the *same* connection while the read loop is idling between
    /// messages. Before the fix, this hung indefinitely — the read
    /// loop held the connection's only lock for the entire blocking
    /// read, starving the second `send()`. Bounded by a timeout so a
    /// regression fails the test instead of hanging CI.
    #[tokio::test]
    async fn test_tcp_send_after_idle_read_does_not_deadlock() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();
        let (mut server_rx, server_sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::new_client(client_addr);
        client.connect(server_addr).await.unwrap();
        let (mut client_rx, client_sender) = client.start();

        let round_trip = async {
            // First message: client -> server -> (small delay to let
            // the read loop go back to idling) -> server -> client.
            client_sender
                .send_to(
                    b"INVITE sip:one@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
                    server_addr,
                )
                .await
                .unwrap();
            let received = server_rx.recv().await.unwrap();
            let reply_dest = received.source;

            // Give the client's read loop time to go back to idling on
            // its blocking read -- this is the window in which the old
            // code held the lock indefinitely.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            server_sender
                .send_to(
                    b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n",
                    reply_dest,
                )
                .await
                .unwrap();
            let _ = client_rx.recv().await.unwrap();

            // Second message on the SAME connection -- this is exactly
            // what deadlocked before the fix.
            client_sender
                .send_to(
                    b"INVITE sip:two@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
                    server_addr,
                )
                .await
                .unwrap();
            let second = server_rx.recv().await.unwrap();
            assert!(second.data.starts_with(b"INVITE sip:two"));
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), round_trip)
            .await
            .expect("second send on a reused TCP connection deadlocked");
    }

    #[tokio::test]
    async fn test_tcp_connection_local_addr() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::new_client(client_addr);
        client.connect(server_addr).await.unwrap();

        // The transport's nominal local_addr is just whatever was
        // passed to new_client (port 0 here) -- connection_local_addr
        // should report the real OS-assigned port instead.
        assert_eq!(client.local_addr().port(), 0);
        let real_local = client.connection_local_addr(server_addr).await.unwrap();
        assert_ne!(real_local.port(), 0);
        assert_eq!(real_local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_tcp_connection_local_addr_unknown_remote() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::new_client(client_addr);
        let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        assert!(client.connection_local_addr(unknown).await.is_none());
    }

    /// `connect()` should bind the outbound connection to a *specific*
    /// requested local port when `new_client` was given a nonzero
    /// port, not just report back whatever the OS happened to assign
    /// (that's `test_tcp_connection_local_addr` above, with `:0`).
    #[tokio::test]
    async fn test_tcp_connect_binds_specific_local_port() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();
        let (mut server_rx, _server_sender) = server.start();

        // Reserve a free ephemeral port the same way a real caller
        // would (bind to :0, read it back, drop the probe socket),
        // then ask `new_client` to use that specific port.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let requested_port = probe.local_addr().unwrap().port();
        drop(probe);

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), requested_port);
        let client = TcpTransport::new_client(client_addr);
        client.connect(server_addr).await.unwrap();

        let real_local = client.connection_local_addr(server_addr).await.unwrap();
        assert_eq!(real_local.port(), requested_port);

        // Sanity: the connection actually works end-to-end from that
        // specific port, not just that the bind succeeded.
        client
            .send_to(
                b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
                server_addr,
            )
            .await
            .unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), server_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(received.data.starts_with(b"INVITE"));
        assert_eq!(received.source.port(), requested_port);
    }

    /// A `:0` port on `new_client` must keep the original OS-assigned
    /// behavior (no regression from the new specific-port bind path).
    #[tokio::test]
    async fn test_tcp_connect_with_zero_port_uses_os_assigned_port() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::new_client(client_addr);
        client.connect(server_addr).await.unwrap();

        let real_local = client.connection_local_addr(server_addr).await.unwrap();
        assert_ne!(real_local.port(), 0);
    }
}
