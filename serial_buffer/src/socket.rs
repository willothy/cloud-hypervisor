// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

    /// Writes out everything still buffered for the client, waiting at most
    /// `timeout` for the client to read it. This is the final flush before
    /// the console goes away, when no later EPOLLOUT edge will finish the
    /// job, and the deadline bounds what a client that stopped reading can
    /// cost the caller.
    ///
    /// Returns once the client's socket has taken every buffered byte, or at
    /// once when no client is attached, since the bytes then have nowhere to
    /// go. Fails with `TimedOut` when bytes are still buffered at the
    /// deadline. A client that hangs up or shuts down its reading side ends
    /// the drain early: with the failed write's own error, such as EPIPE or
    /// ECONNRESET, or with `BrokenPipe` when ppoll reports the hang-up first.
    pub fn drain_output(&self, timeout: Duration) -> io::Result<()> {
        let Some(writable) = self.writable.as_ref() else {
            return Ok(());
        };
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("drain timeout {timeout:?} is out of range"),
            )
        })?;
        loop {
            let pending = {
                let mut buffer = self.buffer.lock().unwrap();
                buffer.write_buffered()?;
                buffer.pending_len()
            };
            if pending == 0 {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    format!("{pending} byte(s) not taken by the client's socket"),
                ));
            }
            let mut pollfd = libc::pollfd {
                fd: writable.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let wait = libc::timespec {
                tv_sec: libc::time_t::try_from(remaining.as_secs()).unwrap_or(libc::time_t::MAX),
                tv_nsec: libc::c_long::from(remaining.subsec_nanos()),
            };
            // SAFETY: `pollfd` and `wait` are locals that outlive the call,
            // the count of 1 matches the single pollfd, whose fd `writable`
            // keeps open throughout, `tv_nsec` is below one second as ppoll
            // requires, and a null signal mask leaves the thread's mask as it
            // is.
            let ret = unsafe { libc::ppoll(&mut pollfd, 1, &wait, ptr::null()) };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    format!("the client hung up with {pending} byte(s) not delivered"),
                ));
            }
        }
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
    use std::net::Shutdown;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};
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

    /// Shrinks the console's send buffer well below what the tests write. A
    /// Unix stream socket's sender is limited by its own send buffer, so
    /// this is what makes the client's socket refuse output with
    /// WouldBlock.
    fn shrink_send_buffer(console: &SocketConsole) {
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
        shrink_send_buffer(&console);

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

    /// Output far larger than the client's socket takes at once, so most of
    /// it stays buffered in the console, as the tail of the guest's output
    /// does when its reader lags.
    fn backlog() -> Vec<u8> {
        (0..512 * 1024).map(|i: usize| (i % 251) as u8).collect()
    }

    #[test]
    fn drain_output_delivers_the_backlog_to_a_slow_client() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        shrink_send_buffer(&console);

        let data = backlog();
        console.out_sink().write_all(&data).unwrap();

        let len = data.len();
        let reader = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut got = vec![0u8; len];
            client.read_exact(&mut got).unwrap();
            got
        });
        console.drain_output(Duration::from_secs(30)).unwrap();
        assert!(reader.join().unwrap() == data, "bytes arrived out of order");
    }

    #[test]
    fn drain_output_gives_up_on_a_stuck_client_at_its_deadline() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let _client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        shrink_send_buffer(&console);
        console.out_sink().write_all(&backlog()).unwrap();

        let timeout = Duration::from_millis(200);
        let start = Instant::now();
        let err = console.drain_output(timeout).unwrap_err();
        let waited = start.elapsed();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(waited >= timeout, "gave up after {waited:?}");
        assert!(waited < Duration::from_secs(10), "waited {waited:?}");
    }

    #[test]
    fn drain_output_stops_when_the_client_hangs_up() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        shrink_send_buffer(&console);
        console.out_sink().write_all(&backlog()).unwrap();
        drop(client);

        // The client left output unread, so the kernel may report the
        // hang-up to the next write as a reset rather than a broken pipe.
        let start = Instant::now();
        let err = console.drain_output(Duration::from_secs(30)).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
            ),
            "unexpected error: {err}"
        );
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn drain_output_stops_when_the_client_stops_reading() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        shrink_send_buffer(&console);
        console.out_sink().write_all(&backlog()).unwrap();
        client.shutdown(Shutdown::Read).unwrap();

        // The console's socket still polls writable, but every write to it
        // fails, so the drain must not wait for the deadline.
        let start = Instant::now();
        let err = console.drain_output(Duration::from_secs(30)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn drain_output_without_a_client_returns_at_once() {
        let console = SocketConsole::new();
        console
            .out_sink()
            .write_all(b"no one is listening\n")
            .unwrap();
        console.drain_output(Duration::from_secs(30)).unwrap();
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
