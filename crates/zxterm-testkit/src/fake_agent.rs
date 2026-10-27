//! A scriptable fake ssh-agent: a Unix-socket listener a test drives however
//! it needs, including K2's SHA-1-answer negative case (an agent that signs
//! with the legacy `ssh-rsa` (SHA-1) algorithm, which a conforming client
//! must refuse).
//!
//! This helper does not itself speak the ssh-agent wire protocol — it hands
//! every accepted connection to a caller-supplied handler, so each test
//! scripts exactly the bytes it needs without this crate guessing at intent
//! it does not have.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// A fake ssh-agent listening on a Unix socket. Each accepted connection is
/// handed to the handler given to `start`, on its own thread.
pub struct FakeAgent {
    socket_path: PathBuf,
    accept_thread: Option<JoinHandle<()>>,
}

impl FakeAgent {
    /// Starts listening on `socket_path` (keep this under a short
    /// `ScratchHome`: the 108-byte Unix-socket path limit is real).
    /// `handler` runs once per accepted connection, on its own thread.
    pub fn start<F>(socket_path: impl AsRef<Path>, handler: F) -> std::io::Result<Self>
    where
        F: Fn(UnixStream) + Send + Sync + 'static,
    {
        let socket_path = socket_path.as_ref().to_path_buf();
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        let handler = Arc::new(handler);
        let accept_thread = thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let handler = Arc::clone(&handler);
                        thread::spawn(move || handler(stream));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(FakeAgent {
            socket_path,
            accept_thread: Some(accept_thread),
        })
    }

    /// The socket path this agent listens on (what a test points
    /// `SSH_AUTH_SOCK` at).
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        // Removing the socket file lets `listener.incoming()` fail its next
        // `accept` once a client stops connecting; the accept thread is
        // otherwise detached rather than joined, so `Drop` never blocks on
        // a client that is slow to disconnect.
        let _ = std::fs::remove_file(&self.socket_path);
        self.accept_thread.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;

    #[test]
    fn echoes_one_line_back_to_the_client() {
        let dir = std::env::temp_dir().join(format!("zxterm-fake-agent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let socket_path = dir.join("agent.sock");

        let _agent = FakeAgent::start(&socket_path, |mut stream: UnixStream| {
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                let _ = stream.write_all(&buf[..n]);
            }
        })
        .expect("start fake agent");

        // Give the accept thread a moment to start listening.
        thread::sleep(Duration::from_millis(20));

        let mut client = UnixStream::connect(&socket_path).expect("connect to fake agent");
        client.write_all(b"hello").expect("write to fake agent");
        let mut response = [0u8; 5];
        client
            .read_exact(&mut response)
            .expect("read from fake agent");
        assert_eq!(&response, b"hello");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
