// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Handing a VM's userfaultfd to an external fault handler.
//!
//! Instead of serving guest-memory faults on an in-process thread, the VMM
//! registers guest RAM on a userfaultfd and hands the descriptor — with the
//! memfds backing guest RAM — to the management software's page server over
//! one long-lived Unix connection. That process then owns every fault: it
//! resolves missing pages from its own storage with `UFFDIO_COPY`, and runs
//! the copy-out of live checkpoints, reading page contents through its own
//! mapping of the memfds. The VMM keeps the connection (and a duplicate of
//! the userfaultfd, for arming write-protection) as a [`FaultSession`].
//!
//! The wire protocol mirrors the page server's (`crucible-pageserver`'s
//! `protocol` module, the layout's authority): every message is an 8-byte
//! header — `type: u32 LE`, `body_len: u32 LE` — followed by `body_len`
//! bytes of JSON, with file descriptors attached to the header bytes as
//! `SCM_RIGHTS`. The VMM sends `Handoff` (type 1, at startup) and `Capture`
//! (type 2, during a live checkpoint's paused phase) and reads
//! `CaptureDone` (type 3) back.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process;
use std::thread::{Builder, JoinHandle};

use log::error;
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

/// Header discriminant of a handoff message.
const MSG_HANDOFF: u32 = 1;
/// Header discriminant of a capture message.
const MSG_CAPTURE: u32 = 2;
/// Header discriminant of a capture-done message.
const MSG_CAPTURE_DONE: u32 = 3;

/// Wire size of the fixed message header.
const HEADER_LEN: usize = 8;

/// Upper bound accepted for a capture-done body, defending the
/// length-prefixed read against a corrupt peer. Done messages carry at most
/// an error string.
const MAX_DONE_LEN: u32 = 1024 * 1024;

/// The fault-handling modes guest RAM was registered with before the
/// handoff.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RegistrationMode {
    /// Missing + write-protect: a demand-paged restore.
    MissingAndWriteProtect,
    /// Write-protect only: a booted (or eagerly restored) VM, registered so
    /// live checkpoints can arm and capture.
    WriteProtectOnly,
}

/// One registered guest-RAM region, described for the peer in both address
/// spaces: this process's (`vmm_addr`, where fault addresses arrive and uffd
/// ioctls act) and the backing memfd's (which the peer maps to read page
/// contents).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffRegion {
    /// Start of the region in this process's address space.
    pub vmm_addr: u64,
    /// Length of the region in bytes.
    pub length: u64,
    /// The region's byte offset in the dense snapshot memory image.
    pub source_offset: u64,
    /// Page size faults arrive and pages are installed at.
    pub page_size: u64,
    /// Index into the handoff's attached memfds of the file backing this
    /// region.
    pub memfd: u32,
    /// Byte offset of the region within that memfd.
    pub memfd_offset: u64,
}

/// The handoff body: the registered guest-RAM layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Handoff {
    mode: RegistrationMode,
    regions: Vec<HandoffRegion>,
}

/// One write-protect-armed range of a live capture, and where its pages land
/// in the output file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRange {
    /// Start of the range in this process's address space.
    pub vmm_addr: u64,
    /// Length of the range in bytes.
    pub length: u64,
    /// Byte offset the range's first page maps to in the output file.
    pub out_offset: u64,
    /// Page size the range is captured and released at.
    pub page_size: u64,
}

/// A live checkpoint's copy-out request.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Capture {
    ranges: Vec<CaptureRange>,
}

/// How a capture ended, reported by the peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum CaptureOutcome {
    Success,
    Failure { error: String },
}

/// The VMM's end of a userfaultfd handoff: the connection to the fault
/// handler and a duplicate of the userfaultfd, kept for arming
/// write-protection during live checkpoints (ioctls do not compete with the
/// peer reading fault events).
pub(crate) struct FaultSession {
    /// Ends the process if the peer hangs up (see [`HangupWatch`]).
    /// Declared first so it stops before the connection closes.
    _hangup: HangupWatch,
    stream: UnixStream,
    uffd: OwnedFd,
}

impl FaultSession {
    /// Connect to the fault handler listening on `socket` and hand it the
    /// registered userfaultfd with the guest-RAM layout. `memfds` are the
    /// files backing the regions, in the order `HandoffRegion::memfd`
    /// indexes.
    pub(crate) fn establish(
        socket: &Path,
        mode: RegistrationMode,
        regions: Vec<HandoffRegion>,
        uffd: OwnedFd,
        memfds: &[RawFd],
    ) -> io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let body = serde_json::to_vec(&Handoff { mode, regions })?;
        let mut fds = Vec::with_capacity(memfds.len() + 1);
        fds.push(uffd.as_raw_fd());
        fds.extend_from_slice(memfds);
        send_message(&stream, MSG_HANDOFF, &body, &fds)?;
        let hangup = HangupWatch::spawn(stream.try_clone()?)?;
        Ok(Self {
            _hangup: hangup,
            stream,
            uffd,
        })
    }

    /// The userfaultfd, for arming write-protection.
    pub(crate) fn uffd(&self) -> BorrowedFd<'_> {
        self.uffd.as_fd()
    }

    /// Send a live capture's copy-out request: the armed ranges, with the
    /// pre-sized output file attached. The peer owns the capture once this
    /// returns; completion arrives as a capture-done message on the
    /// connection (see [`Self::wait_done`]).
    pub(crate) fn send_capture(&self, ranges: Vec<CaptureRange>, out: &File) -> io::Result<()> {
        let body = serde_json::to_vec(&Capture { ranges })?;
        send_message(&self.stream, MSG_CAPTURE, &body, &[out.as_raw_fd()])
    }

    /// A duplicate of the connection for waiting on a capture-done message
    /// without holding whatever lock guards this session.
    pub(crate) fn try_clone_stream(&self) -> io::Result<UnixStream> {
        self.stream.try_clone()
    }

    /// Read one capture-done message from `stream` (a clone of the session's
    /// connection), blocking until the peer finishes the capture. Returns
    /// the peer's outcome: `Ok` when every armed page was captured, or the
    /// error that aborted the capture.
    pub(crate) fn wait_done(stream: &UnixStream) -> io::Result<Result<(), String>> {
        let mut header = [0u8; HEADER_LEN];
        (&mut &*stream).read_exact(&mut header)?;
        let message_type = u32::from_le_bytes(header[0..4].try_into().expect("4-byte slice"));
        let body_len = u32::from_le_bytes(header[4..8].try_into().expect("4-byte slice"));
        if message_type != MSG_CAPTURE_DONE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected message type {message_type} from the fault handler"),
            ));
        }
        if body_len > MAX_DONE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("capture-done body of {body_len} bytes exceeds the bound"),
            ));
        }
        let mut body = vec![0u8; body_len as usize];
        (&mut &*stream).read_exact(&mut body)?;
        match serde_json::from_slice(&body)? {
            CaptureOutcome::Success => Ok(Ok(())),
            CaptureOutcome::Failure { error } => Ok(Err(error)),
        }
    }
}

/// Watches a fault session's connection for the fault handler hanging up.
///
/// The handler owns every fault on guest RAM. Once it is gone, a vCPU that
/// touches a missing or write-protected page sleeps in the kernel until a
/// fatal signal, so the VM can neither run nor shut down. On a hangup the
/// watch logs it and exits the process without recording an exit reason:
/// the VMM can no longer run the VM, and its manager restores the VM from
/// its last checkpoint.
///
/// Only `POLLRDHUP` is polled for, so capture-done messages stay queued for
/// [`FaultSession::wait_done`].
struct HangupWatch {
    stop: EventFd,
    thread: Option<JoinHandle<()>>,
}

impl HangupWatch {
    /// Start watching `stream`, a clone of the session's connection.
    fn spawn(stream: UnixStream) -> io::Result<Self> {
        let stop = EventFd::new(0)?;
        let stopped = stop.try_clone()?;
        let thread = Builder::new()
            .name("fault_hangup".to_string())
            .spawn(move || Self::watch(&stream, &stopped))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Block until `stop` is signalled, returning, or the peer hangs up,
    /// ending the process.
    fn watch(stream: &UnixStream, stop: &EventFd) {
        let mut fds = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLRDHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: `fds` is an array of two initialized pollfds whose
            // descriptors stay open for the duration of the call.
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // An unwatched session would leave a hangup to wedge the
                // VM, so losing the watch ends the VM as a hangup does.
                error!("watching the fault-handler connection failed: {error}");
                Self::exit();
            }
            if fds[1].revents != 0 {
                return;
            }
            if fds[0].revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0 {
                error!(
                    "the fault handler closed the VM's fault session; guest memory can no longer be served"
                );
                Self::exit();
            }
        }
    }

    /// End the process, flushing the log first.
    fn exit() -> ! {
        log::logger().flush();
        process::exit(1)
    }
}

impl Drop for HangupWatch {
    fn drop(&mut self) {
        if let Err(error) = self.stop.write(1) {
            error!("stopping the fault-handler hangup watch failed: {error}");
            return;
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            error!("the fault-handler hangup watch panicked");
        }
    }
}

/// Send one message: the 8-byte header with `fds` attached as `SCM_RIGHTS`,
/// then the JSON body. The descriptors ride the first byte, so a partial
/// send (a large capture body interrupted mid-write) resumes with plain
/// writes without re-sending them.
fn send_message(
    stream: &UnixStream,
    message_type: u32,
    body: &[u8],
    fds: &[RawFd],
) -> io::Result<()> {
    let body_len = u32::try_from(body.len())
        .map_err(|_| io::Error::other("message body exceeds the u32 length field"))?;
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&message_type.to_le_bytes());
    header[4..8].copy_from_slice(&body_len.to_le_bytes());
    let sent = stream
        .send_with_fds(&[&header[..], body], fds)
        .map_err(|e| io::Error::other(format!("sendmsg to the fault handler: {e}")))?;
    if sent < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short header write on the fault-handler connection",
        ));
    }
    use std::io::Write;
    (&mut &*stream).write_all(&body[sent - HEADER_LEN..])
}
