//! A minimal raw-TCP loopback HTTP server for `tests/github_keys_ported.rs`
//! (porting `test/github-keys.test.js`'s own hand-rolled `serve(t, handler)`
//! helper, which drives Node's `http.createServer` directly so a test can
//! return arbitrary statuses, redirects, oversized bodies or a stalled
//! response). `zxterm_testkit::KeysServer` only ever answers 200/404 for a
//! configured user, which is not enough for those cases, so this lives
//! beside `tests/support/mod.rs` instead of extending that shared testkit
//! type.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Called once per accepted connection with the request path (e.g.
/// `/octocat.keys`) and the still-open stream to write a raw HTTP/1.1
/// response to.
pub type Handler = Arc<dyn Fn(&str, &mut TcpStream) + Send + Sync>;

pub struct RawServer {
    pub base_url: String,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl RawServer {
    pub fn start(handler: Handler) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let accept_thread = thread::spawn(move || {
            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let handler = Arc::clone(&handler);
                        thread::spawn(move || {
                            if let Some(path) = read_request_path(&mut stream) {
                                handler(&path, &mut stream);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(RawServer {
            base_url: format!("http://{addr}"),
            addr,
            stop,
            accept_thread: Some(accept_thread),
        })
    }
}

impl Drop for RawServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // A connection thread stuck simulating a stall (see
        // `respond_partial_and_stall`) is left to time out on its own; the
        // accept loop itself exits within one `WouldBlock` sleep tick.
        self.accept_thread.take();
        let _ = TcpStream::connect(self.addr); // nudge a blocked accept() awake
    }
}

fn read_request_path(stream: &mut TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let path = request_line.split_whitespace().nth(1)?.to_string();
    loop {
        let mut header_line = String::new();
        match reader.read_line(&mut header_line) {
            Ok(0) => break,
            Ok(_) if header_line == "\r\n" || header_line == "\n" => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Some(path)
}

/// Writes a well-formed `HTTP/1.1 <status> <reason>` response with
/// `headers` and `body`, setting `Content-Length` itself.
pub fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(body);
}

/// Writes response headers plus a partial body with no `Content-Length`
/// (chunked-less, connection-close framing), then blocks well past any
/// sane test timeout without ever finishing the body or closing — a
/// stalled response, mirroring `github-keys.test.js`'s `res.write(...)`
/// with no matching `res.end()`.
pub fn respond_partial_and_stall(stream: &mut TcpStream, partial_body: &[u8]) {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(partial_body);
    let _ = stream.flush();
    thread::sleep(Duration::from_secs(2));
    // Drain-and-drop rather than an explicit close: the peer's own timeout
    // should have already fired well before this returns.
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);
}
