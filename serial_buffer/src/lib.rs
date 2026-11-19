// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod socket;
pub use socket::SocketConsole;

const MAX_BUFFER_SIZE: usize = 1 << 20;

// Circular buffer implementation for serial output.
// Read from head; push to tail
pub struct SerialBuffer {
    buffer: VecDeque<u8>,
    out: Box<dyn Write + Send>,
    write_out: Arc<AtomicBool>,
}

impl SerialBuffer {
    pub fn new(out: Box<dyn Write + Send>, write_out: Arc<AtomicBool>) -> Self {
        Self {
            buffer: VecDeque::new(),
            out,
            write_out,
        }
    }

    fn fill_buffer(&mut self, buf: &[u8]) {
        if buf.len() >= MAX_BUFFER_SIZE {
            let offset = buf.len() - MAX_BUFFER_SIZE;
            self.buffer = VecDeque::from(buf[offset..].to_vec());
            return;
        }

        let num_allowed_bytes = MAX_BUFFER_SIZE - buf.len();
        if self.buffer.len() > num_allowed_bytes {
            let num_bytes_to_remove = self.buffer.len() - num_allowed_bytes;
            self.buffer.drain(..num_bytes_to_remove);
        }

        self.buffer.extend(buf);
    }

    /// Replaces the downstream writer, leaving any buffered bytes intact.
    pub fn set_out(&mut self, out: Box<dyn Write + Send>) {
        self.out = out;
    }

    /// Returns how many bytes are buffered, not yet written to the out
    /// device.
    fn pending_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Write for SerialBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Simply fill the buffer if we're not allowed to write to the out
        // device.
        if !self.write_out.load(Ordering::Acquire) {
            self.fill_buffer(data);
            return Ok(data.len());
        }

        // In case we're allowed to write to the out device, we flush the
        // content of the buffer.
        self.flush()?;

        // If after flushing the buffer, it's still not empty, that means
        // only a subset of the bytes was written and we should fill the buffer
        // with what's coming from the serial.
        if !self.buffer.is_empty() {
            self.fill_buffer(data);
            return Ok(data.len());
        }

        // First try writing directly to the output device; if that fails,
        // buffer the data in memory for later.
        let mut offset = 0;
        while offset < data.len() {
            match self.out.write(&data[offset..]) {
                Ok(0) => {
                    self.fill_buffer(&data[offset..]);
                    break;
                }
                Ok(written) => {
                    offset += written;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.fill_buffer(&data[offset..]);
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        // Make sure we flush anything that might have been written to the
        // out device.
        self.out.flush()?;

        Ok(data.len())
    }

    // This function flushes the content of the buffer to the out device if
    // it is allowed to, otherwise this is a no-op. It writes the buffer's
    // contiguous runs whole, and stops at the first write that would block
    // or fails, keeping every byte not yet written for the next flush.
    fn flush(&mut self) -> io::Result<()> {
        if !self.write_out.load(Ordering::Acquire) {
            return Ok(());
        }

        while !self.buffer.is_empty() {
            let (front, _) = self.buffer.as_slices();
            match self.out.write(front) {
                // The out device takes nothing more for now.
                Ok(0) => break,
                Ok(written) => {
                    self.buffer.drain(..written);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::SerialBuffer;

    // A writer that appends into a shared Vec so tests can inspect what the
    // buffer wrote through to its downstream sink.
    #[derive(Clone)]
    struct TestSink(Arc<Mutex<Vec<u8>>>);

    impl TestSink {
        fn new() -> Self {
            TestSink(Arc::new(Mutex::new(Vec::new())))
        }
        fn taken(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Write for TestSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // A writer that refuses with WouldBlock until `accept` is set, as a
    // non-blocking socket does while its send buffer is full, then takes at
    // most `limit` bytes per write, counting its writes.
    #[derive(Clone)]
    struct FullSink {
        taken: Arc<Mutex<Vec<u8>>>,
        accept: Arc<AtomicBool>,
        limit: usize,
        writes: Arc<Mutex<usize>>,
    }

    impl FullSink {
        fn new(limit: usize) -> Self {
            FullSink {
                taken: Arc::new(Mutex::new(Vec::new())),
                accept: Arc::new(AtomicBool::new(false)),
                limit,
                writes: Arc::new(Mutex::new(0)),
            }
        }
        fn taken(&self) -> Vec<u8> {
            self.taken.lock().unwrap().clone()
        }
        fn writes(&self) -> usize {
            *self.writes.lock().unwrap()
        }
    }

    impl Write for FullSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.accept.load(Ordering::Acquire) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            *self.writes.lock().unwrap() += 1;
            let taken = buf.len().min(self.limit);
            self.taken.lock().unwrap().extend_from_slice(&buf[..taken]);
            Ok(taken)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Bytes a full out device refuses are kept, in order, and leave on the
    // next flush once it takes them: in one write per contiguous run of the
    // buffer, not one per byte.
    #[test]
    fn bytes_refused_while_full_leave_in_order_on_flush() {
        let write_out = Arc::new(AtomicBool::new(true));
        let sink = FullSink::new(usize::MAX);
        let mut buf = SerialBuffer::new(Box::new(sink.clone()), write_out);

        buf.write_all(b"the tail of a line").unwrap();
        buf.write_all(b" and more").unwrap();
        assert!(sink.taken().is_empty());

        sink.accept.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert_eq!(sink.taken(), b"the tail of a line and more");
        assert_eq!(sink.writes(), 1);

        buf.flush().unwrap();
        assert_eq!(sink.taken(), b"the tail of a line and more");
    }

    // A write that takes only part of what is buffered keeps the rest for
    // the next flush.
    #[test]
    fn a_partial_write_keeps_the_rest() {
        let write_out = Arc::new(AtomicBool::new(true));
        let refuses_every_write = FullSink::new(usize::MAX);
        let mut buf = SerialBuffer::new(Box::new(refuses_every_write.clone()), write_out);
        buf.write_all(b"0123456789").unwrap();

        let partial = FullSink::new(4);
        partial.accept.store(true, Ordering::Release);
        buf.set_out(Box::new(OnceThenFull {
            sink: partial.clone(),
            writes_left: 1,
        }));
        buf.flush().unwrap();
        assert_eq!(partial.taken(), b"0123");

        let rest = FullSink::new(usize::MAX);
        rest.accept.store(true, Ordering::Release);
        buf.set_out(Box::new(rest.clone()));
        buf.flush().unwrap();
        assert_eq!(rest.taken(), b"456789");
    }

    // Writes through `sink` `writes_left` times, then refuses with
    // WouldBlock.
    struct OnceThenFull {
        sink: FullSink,
        writes_left: usize,
    }

    impl Write for OnceThenFull {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.writes_left == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.writes_left -= 1;
            self.sink.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // With no client attached (write_out == false) output is retained in the
    // ring and replayed in order once a client connects (set_out + write_out).
    #[test]
    fn accumulates_while_detached_then_replays_on_connect() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), Arc::clone(&write_out));

        buf.write_all(b"boot: hello\n").unwrap();
        buf.write_all(b"login: ").unwrap();

        let sink = TestSink::new();
        buf.set_out(Box::new(sink.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();

        assert_eq!(sink.taken(), b"boot: hello\nlogin: ");
    }

    // Once connected, live writes pass straight through.
    #[test]
    fn live_writes_pass_through_after_connect() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), Arc::clone(&write_out));

        let sink = TestSink::new();
        buf.set_out(Box::new(sink.clone()));
        write_out.store(true, Ordering::Release);
        buf.write_all(b"live").unwrap();

        assert_eq!(sink.taken(), b"live");
    }

    // Output produced while no client is attached is buffered and delivered to
    // the next client to connect; bytes already drained by a previous client
    // are not resent.
    #[test]
    fn output_while_detached_goes_to_next_client() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), Arc::clone(&write_out));

        // First client: connects, drains "early\n", then disconnects.
        let first = TestSink::new();
        buf.set_out(Box::new(first.clone()));
        write_out.store(true, Ordering::Release);
        buf.write_all(b"early\n").unwrap();
        assert_eq!(first.taken(), b"early\n");

        // Disconnect: detach to a discarding sink, keep accumulating.
        write_out.store(false, Ordering::Release);
        buf.set_out(Box::new(io::sink()));
        buf.write_all(b"while-away\n").unwrap();

        // Second client: receives what was produced while no one was attached.
        let second = TestSink::new();
        buf.set_out(Box::new(second.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert_eq!(second.taken(), b"while-away\n");
    }

    // Bytes are delivered once: a second client connecting after the first
    // already drained the backlog, with no new output in between, gets nothing.
    #[test]
    fn drained_bytes_are_not_resent_to_a_second_client() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), Arc::clone(&write_out));

        buf.write_all(b"boot log\n").unwrap();

        // First client drains the backlog.
        let first = TestSink::new();
        buf.set_out(Box::new(first.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert_eq!(first.taken(), b"boot log\n");

        // First disconnects; no new output is produced while detached.
        write_out.store(false, Ordering::Release);
        buf.set_out(Box::new(io::sink()));

        // Second client connects: nothing left to deliver.
        let second = TestSink::new();
        buf.set_out(Box::new(second.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert!(second.taken().is_empty());
    }
}
