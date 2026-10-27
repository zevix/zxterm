//! A loopback HTTP server that serves `GET /<user>.keys` bodies a test
//! configures, standing in for `https://github.com/<user>.keys` so no test
//! ever reaches `github.com` (`A-9`). K3's GitHub identity parity tests
//! point the engine's GitHub base URL at this server instead.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Looks up the `.keys` body for a GitHub login, or `None` for a 404.
pub type KeysLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// A loopback `.keys` HTTP server on `127.0.0.1`.
pub struct KeysServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl KeysServer {
    /// Starts listening on a free `127.0.0.1` port. `lookup` answers each
    /// `GET /<user>.keys` request.
    pub fn start(lookup: KeysLookup) -> std::io::Result<Self> {
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
                    Ok((stream, _)) => {
                        let lookup = Arc::clone(&lookup);
                        thread::spawn(move || handle_connection(stream, &lookup));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(KeysServer {
            addr,
            stop,
            accept_thread: Some(accept_thread),
        })
    }

    /// This server's loopback base URL, e.g. `http://127.0.0.1:54321`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

fn handle_connection(mut stream: TcpStream, lookup: &KeysLookup) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let user = path.trim_start_matches('/').trim_end_matches(".keys");

    // Drain the request headers; this server never needs them.
    loop {
        let mut header_line = String::new();
        match reader.read_line(&mut header_line) {
            Ok(0) => break,
            Ok(_) if header_line == "\r\n" || header_line == "\n" => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let response = match lookup(user) {
        Some(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
        None => {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        }
    };
    let _ = stream.write_all(response.as_bytes());
}

impl Drop for KeysServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.accept_thread.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn serves_a_configured_users_keys() {
        let server = KeysServer::start(Arc::new(|user: &str| {
            if user == "octocat" {
                Some("ssh-ed25519 AAAAtest octocat\n".to_string())
            } else {
                None
            }
        }))
        .expect("start keys server");

        let body = get(&server, "/octocat.keys");
        assert!(body.contains("200 OK"));
        assert!(body.contains("ssh-ed25519 AAAAtest octocat"));

        let missing = get(&server, "/nobody.keys");
        assert!(missing.contains("404"));
    }

    fn get(server: &KeysServer, path: &str) -> String {
        let mut stream = TcpStream::connect(server.addr).expect("connect to keys server");
        write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write request");
        let mut response = String::new();
        stream.read_to_string(&mut response).ok();
        response
    }
}
