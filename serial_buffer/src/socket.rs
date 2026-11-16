// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::SerialBuffer;

struct SharedSerialBuffer(Arc<Mutex<SerialBuffer>>);

impl Write for SharedSerialBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

/// Serves a device byte stream over a socket to one client at a time, buffering
/// output until a client connects.
pub struct SocketConsole {
    buffer: Arc<Mutex<SerialBuffer>>,
    write_out: Arc<AtomicBool>,
    reader: Option<UnixStream>,
    /// A dup of the client's fd for the caller to watch for EPOLLOUT,
    /// edge-triggered, apart from the level-triggered EPOLLIN on `reader`.
    /// It is opened and closed with `reader`: an epoll entry belongs to the
    /// open file, so closing every fd on it is what drops the entries.
    writable: Option<UnixStream>,
}

impl Default for SocketConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketConsole {
    pub fn new() -> Self {
        let write_out = Arc::new(AtomicBool::new(false));
        let buffer = Arc::new(Mutex::new(SerialBuffer::new(
            Box::new(io::sink()),
            Arc::clone(&write_out),
        )));
        Self {
            buffer,
            write_out,
            reader: None,
            writable: None,
        }
    }

    pub fn out_sink(&self) -> Box<dyn Write + Send> {
        Box::new(SharedSerialBuffer(Arc::clone(&self.buffer)))
    }

    /// Returns the connected client fd, or None when no client is attached.
    pub fn client_fd(&self) -> Option<RawFd> {
        self.reader.as_ref().map(|stream| stream.as_raw_fd())
    }

    /// Returns the fd to watch for EPOLLOUT, or None when no client is
    /// attached. Watch it edge-triggered and call [`Self::flush_output`] on
    /// each edge.
    pub fn writable_fd(&self) -> Option<RawFd> {
        self.writable.as_ref().map(|stream| stream.as_raw_fd())
    }

    /// Writes out what the client's socket refused earlier. Without this,
    /// bytes buffered on WouldBlock wait for the device's next write, which
    /// may never come.
    pub fn flush_output(&self) -> io::Result<()> {
        self.buffer.lock().unwrap().flush()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        if let Some(stream) = self.reader.take() {
            let res = stream.shutdown(Shutdown::Both);
            self.detach();
            res?;
        }
        Ok(())
    }

    pub fn accept(&mut self, listener: &UnixListener) -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        stream.set_nonblocking(true)?;
        let writer = stream.try_clone()?;
        let writable = stream.try_clone()?;
        self.attach(Box::new(writer))?;
        self.reader = Some(stream);
        self.writable = Some(writable);
        Ok(())
    }

    fn attach(&self, writer: Box<dyn Write + Send>) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.set_out(writer);
        self.write_out.store(true, Ordering::Release);
        buffer.flush()
    }

    fn detach(&mut self) {
        self.writable = None;
        self.write_out.store(false, Ordering::Release);
        self.buffer.lock().unwrap().set_out(Box::new(io::sink()));
    }
}

impl Read for SocketConsole {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(mut stream) = self.reader.as_ref() else {
            return Ok(0);
        };
        match stream.read(buf) {
            Ok(count) if count > 0 => Ok(count),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            ended => {
                let _ = stream.shutdown(Shutdown::Both);
                self.reader = None;
                self.detach();
                ended
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;
    use std::{fs, thread};

    use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
    use vmm_sys_util::tempdir::TempDir;

    use super::SocketConsole;

    const READABLE: u64 = 0;
    const WRITABLE: u64 = 3;

    fn read_retry(console: &mut SocketConsole, buf: &mut [u8]) -> usize {
        for _ in 0..200 {
            let n = console.read(buf).unwrap();
            if n > 0 {
                return n;
            }
            thread::sleep(Duration::from_millis(1));
        }
        0
    }

    #[test]
    fn replays_buffered_output_to_client_on_connect() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut sink = console.out_sink();
        sink.write_all(b"boot\n").unwrap();

        let mut client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();

        let mut got = [0u8; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"boot\n");
    }

    #[test]
    fn reads_input_from_connected_client() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();

        client.write_all(b"hi").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 8];
        let n = read_retry(&mut console, &mut buf);
        assert_eq!(&buf[..n], b"hi");
    }

    #[test]
    fn shutdown_then_accept_replaces_client() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut first = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();

        let second = UnixStream::connect(&path).unwrap();
        console.shutdown().unwrap();
        console.accept(&listener).unwrap();

        // shutdown() closed the first connection.
        let mut discard = [0u8; 4];
        assert_eq!(first.read(&mut discard).unwrap(), 0);

        let mut sink = console.out_sink();
        sink.write_all(b"hey\n").unwrap();
        let mut got = [0u8; 4];
        (&second).read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hey\n");
    }

    #[test]
    fn reports_connection_state() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();
        assert!(console.client_fd().is_none());

        let _client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        assert!(console.client_fd().is_some());
    }

    #[test]
    fn writable_fd_follows_the_client() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();
        assert!(console.writable_fd().is_none());

        let _client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        assert!(console.writable_fd().is_some());
        assert_ne!(console.writable_fd(), console.client_fd());

        console.shutdown().unwrap();
        assert!(console.writable_fd().is_none());
    }

    /// Counts the fds `epoll` watches, as the kernel lists them in its
    /// fdinfo: an entry stays listed until its open file is released.
    fn watched_fds(epoll: &Epoll) -> usize {
        fs::read_to_string(format!("/proc/self/fdinfo/{}", epoll.as_raw_fd()))
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("tfd:"))
            .count()
    }

    /// Watches the console's client as the serial manager does: EPOLLIN on
    /// the reader, level-triggered, and EPOLLOUT on the writable fd,
    /// edge-triggered.
    fn watch_like_the_serial_manager(console: &SocketConsole) -> Epoll {
        let epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                console.client_fd().unwrap(),
                EpollEvent::new(EventSet::IN, READABLE),
            )
            .unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                console.writable_fd().unwrap(),
                EpollEvent::new(EventSet::OUT | EventSet::EDGE_TRIGGERED, WRITABLE),
            )
            .unwrap();
        epoll
    }

    #[test]
    fn an_epollout_edge_flushes_what_the_client_refused() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        client.set_nonblocking(true).unwrap();

        // A Unix stream socket's sender is limited by its own send buffer,
        // so shrink the console's well below what the test writes.
        let sndbuf: libc::c_int = 64 * 1024;
        // SAFETY: the fd is the console's open socket, and the option value
        // points at a c_int that outlives the call, with its size passed.
        let ret = unsafe {
            libc::setsockopt(
                console.writable_fd().unwrap(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const sndbuf).cast(),
                libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap(),
            )
        };
        assert_eq!(ret, 0, "setsockopt: {}", io::Error::last_os_error());

        let epoll = watch_like_the_serial_manager(&console);
        let mut events = [EpollEvent::default(); 4];

        // The socket was empty when it was registered, so it reports
        // writable once.
        assert_eq!(epoll.wait(0, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), WRITABLE);

        // Far larger than the socket's buffer, so part of it is refused
        // with WouldBlock and stays in the console's buffer.
        let data: Vec<u8> = (0..512 * 1024).map(|i: usize| (i % 251) as u8).collect();
        console.out_sink().write_all(&data).unwrap();
        assert_eq!(epoll.wait(0, &mut events).unwrap(), 0);

        let mut got = Vec::with_capacity(data.len());
        let mut buf = [0u8; 4096];
        let mut flushes = 0;
        loop {
            match client.read(&mut buf) {
                Ok(0) => panic!("the console closed the connection"),
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    continue;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("reading from the console failed: {e}"),
            }
            if got.len() == data.len() {
                break;
            }
            // The peer drained the socket with bytes still buffered, so the
            // writable fd must report an edge, and flushing on it must
            // deliver more.
            let n = epoll.wait(1000, &mut events).unwrap();
            assert_eq!(n, 1, "no edge with {} of {} bytes", got.len(), data.len());
            assert_eq!(events[0].data(), WRITABLE);
            console.flush_output().unwrap();
            flushes += 1;
        }
        assert!(flushes > 0, "no byte waited for an EPOLLOUT edge");
        assert!(got == data, "bytes arrived out of order");
    }

    #[test]
    fn dropping_the_client_drops_its_epoll_entries() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        // Shut down by the console's owner, without removing the entries.
        let _client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        let epoll = watch_like_the_serial_manager(&console);
        assert_eq!(watched_fds(&epoll), 2);
        console.shutdown().unwrap();
        assert_eq!(watched_fds(&epoll), 0);

        // Closed by the peer, seen by the console's read.
        let client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        let epoll = watch_like_the_serial_manager(&console);
        assert_eq!(watched_fds(&epoll), 2);
        drop(client);
        let mut buf = [0u8; 8];
        assert_eq!(console.read(&mut buf).unwrap(), 0);
        assert!(console.client_fd().is_none());
        assert_eq!(watched_fds(&epoll), 0);
    }

    #[test]
    fn client_reset_with_unread_output_does_not_wedge_console() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        {
            let _client = UnixStream::connect(&path).unwrap();
            console.accept(&listener).unwrap();
            assert!(console.client_fd().is_some());

            let mut sink = console.out_sink();
            sink.write_all(&vec![b'x'; 64 * 1024]).unwrap();
        }

        let mut buf = [0u8; 64];
        let mut reset = None;
        for _ in 0..1000 {
            match console.read(&mut buf) {
                Ok(0) if console.client_fd().is_some() => {
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(n) => panic!("expected a connection reset, got {n} readable byte(s)"),
                Err(e) => {
                    reset = Some(e);
                    break;
                }
            }
        }
        let reset = reset.expect("connection reset was never observed");
        assert_eq!(reset.kind(), ErrorKind::ConnectionReset);

        assert!(console.client_fd().is_none());

        let mut next = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        let mut sink = console.out_sink();
        sink.write_all(b"back\n").unwrap();
        let mut got = [0u8; 5];
        next.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"back\n");
    }
}
