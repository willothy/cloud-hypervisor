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
//! `CaptureDone` (type 3) back. While guest RAM is demand-paged, it also
//! relays `BackendHandoff` (type 4): each memory table a vhost-user backend
//! mapped and registered with its own userfaultfd, through the vhost-user
//! postcopy flow, so that backend's first touch of a page not yet served
//! faults to the handler instead of landing a zero page in guest RAM. The
//! first handoff of a vhost-user connection carries its userfaultfd, and
//! later ones on the same connection name it by the connection's id. Each
//! handoff carries one end of a socket pair, on which the handler answers
//! with `BackendVerdict` (type 5) once it has adopted the table or refused
//! it.
//!
//! A demand-paged session ends its demand paging with `Settle` (type 6):
//! the VMM asks whether the handler has served the whole memory image, and
//! the handler answers on the connection with `SettleVerdict` (type 7).
//! Once it has, it stops serving missing faults — it unregisters every
//! backend's mappings and registers this process's guest RAM again
//! write-protect-only — and answers that guest RAM is settled; from then on
//! the session is a booted VM's, kept for live checkpoints alone. Before
//! that it answers that it is not yet, and nothing changes. The settle
//! message carries the version of the exchange the VMM speaks, which a
//! handler speaking another refuses.

use std::fs::{self, File};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, JoinHandle};
use std::{io, process};

use log::error;
use serde::{Deserialize, Serialize};
use virtio_devices::vhost_user::{BackendFaultHandler, BackendMapping};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

/// Header discriminant of a handoff message.
const MSG_HANDOFF: u32 = 1;
/// Header discriminant of a capture message.
const MSG_CAPTURE: u32 = 2;
/// Header discriminant of a capture-done message.
const MSG_CAPTURE_DONE: u32 = 3;
/// Header discriminant of a backend-handoff message.
const MSG_BACKEND_HANDOFF: u32 = 4;
/// Header discriminant of a backend-verdict message.
const MSG_BACKEND_VERDICT: u32 = 5;
/// Header discriminant of a settle message.
const MSG_SETTLE: u32 = 6;
/// Header discriminant of a settle-verdict message.
const MSG_SETTLE_VERDICT: u32 = 7;

/// The version of the settle exchange this VMM speaks, sent in every settle
/// message. A handler that speaks another version refuses the message with
/// a reason rather than answering in a shape this side would misread.
const SETTLE_VERSION: u32 = 1;

/// Wire size of the fixed message header.
const HEADER_LEN: usize = 8;

/// Upper bound accepted for the body of a message from the fault handler,
/// defending the length-prefixed read against a corrupt peer. Its messages
/// carry at most an error string.
const MAX_RECEIVED_LEN: u32 = 1024 * 1024;

/// The most bytes of a capture body the fault handler reads, mirroring its own
/// bound (`crucible-pageserver`'s `protocol::MAX_BODY_LEN`, the wire
/// contract's authority). A capture's body is its armed ranges as JSON, which
/// a fragmented dirty set of the platform's largest VM brings to 964 MB. A
/// body past the bound is refused here, failing that one checkpoint with a
/// reason: sending it would end the session, which the VM cannot survive.
const MAX_CAPTURE_BODY_LEN: usize = 1 << 30;

/// The reason the VMM records when it exits because its fault session is gone.
/// Its manager settles a VMM that recorded this as failed, rather than as one
/// that crashed and is restored from its latest checkpoint.
const SESSION_LOST: &str = "session-lost";

/// The fault-handling modes guest RAM was registered with before the
/// handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RegistrationMode {
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
pub(crate) struct HandoffRegion {
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
pub(crate) struct CaptureRange {
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

/// One of a vhost-user backend's mappings of guest RAM: where it sits in the
/// backend's address space and the range of this process's it maps.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackendRegion {
    /// Start of the mapping in the backend's address space.
    backend_addr: u64,
    /// Where this process maps the mapping's first byte.
    vmm_addr: u64,
    /// Length of the mapping in bytes.
    length: u64,
    /// The page size of the mapping's backing.
    page_size: u64,
}

/// The backend-handoff body: which device's backend, on which connection,
/// and the mappings of its memory table. Its descriptors are the verdict
/// socket, then the connection's userfaultfd on its first handoff only.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackendHandoff {
    device: String,
    connection: u64,
    regions: Vec<BackendRegion>,
}

/// The handler's answer to a backend handoff, on the handoff's verdict
/// socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum BackendVerdict {
    /// The handler serves the table's faults.
    Adopted,
    /// The handler refused the table, so the backend must not touch it.
    Rejected { error: String },
}

/// How a capture ended, reported by the peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum CaptureOutcome {
    Success,
    Failure { error: String },
}

/// The settle body: asks the handler whether it has served the whole memory
/// image, and to end demand paging if it has.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settle {
    /// The version of the exchange the sender speaks.
    version: u32,
}

/// The handler's answer to a settle.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SettleVerdict {
    /// The image is fully served and missing faults are no longer trapped:
    /// guest RAM is registered write-protect-only from now on.
    Settled,
    /// The image is not fully served yet. Nothing changed.
    NotYet,
    /// The handler refused the settle, for the reason it gives. Nothing
    /// changed.
    Refused { error: String },
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
    mode: RegistrationMode,
    /// Serializes whole messages onto the connection: captures are sent from
    /// here, and backend handoffs from the [`BackendFaultRelay`]s of
    /// vhost-user devices, which can connect at any time.
    write: Arc<Mutex<()>>,
    /// Held by every [`BackendFaultRelay`] this session handed out, so the
    /// session can tell whether a vhost-user device still holds one.
    relays: Arc<()>,
}

impl FaultSession {
    /// Connect to the fault handler listening on `socket` and hand it the
    /// registered userfaultfd with the guest-RAM layout. `memfds` are the
    /// files backing the regions, in the order `HandoffRegion::memfd`
    /// indexes. `exit_reason` is where the VMM records why it exits, which a
    /// lost session's hangup watch writes before ending the process.
    pub(crate) fn establish(
        socket: &Path,
        mode: RegistrationMode,
        regions: Vec<HandoffRegion>,
        uffd: OwnedFd,
        memfds: &[RawFd],
        exit_reason: Option<&Path>,
    ) -> io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let body = serde_json::to_vec(&Handoff { mode, regions })?;
        let mut fds = Vec::with_capacity(memfds.len() + 1);
        fds.push(uffd.as_raw_fd());
        fds.extend_from_slice(memfds);
        send_message(&stream, MSG_HANDOFF, &body, &fds)?;
        let hangup = HangupWatch::spawn(stream.try_clone()?, exit_reason)?;
        Ok(Self {
            _hangup: hangup,
            stream,
            uffd,
            mode,
            write: Arc::new(Mutex::new(())),
            relays: Arc::new(()),
        })
    }

    /// Whether guest RAM is demand-paged through this session, as opposed to
    /// only write-protected for captures.
    pub(crate) fn demand_paged(&self) -> bool {
        self.mode == RegistrationMode::MissingAndWriteProtect
    }

    /// The relay vhost-user devices hand their backends' userfaultfds to,
    /// when guest RAM is demand-paged through this session; `None` for a
    /// write-protect-only session, whose guest RAM has nothing to serve, a
    /// settled one included.
    pub(crate) fn backend_fault_relay(&self) -> io::Result<Option<BackendFaultRelay>> {
        if !self.demand_paged() {
            return Ok(None);
        }
        Ok(Some(BackendFaultRelay {
            stream: self.stream.try_clone()?,
            write: Arc::clone(&self.write),
            _session: Arc::clone(&self.relays),
        }))
    }

    /// Whether a vhost-user device still holds a relay this session handed
    /// out while guest RAM was demand-paged. Such a device keeps its
    /// backend on the postcopy flow for its whole life, settled or not, and
    /// a backend on that flow takes no added memory region.
    pub(crate) fn relays_backends(&self) -> bool {
        Arc::strong_count(&self.relays) > 1
    }

    /// Ask the fault handler whether it has served the whole memory image,
    /// and have it end demand paging if so. Returns whether guest RAM is
    /// settled: `true` once the handler has registered it write-protect-only
    /// — from then on this is a booted VM's session, with no backend fault
    /// relay to hand out — and at once for a session that never was, or no
    /// longer is, demand-paged; `false` while the image is still being
    /// served, when nothing has changed.
    ///
    /// The verdict is read from the connection capture-done messages arrive
    /// on, so the caller must hold the exclusion a live capture holds over
    /// the session: the VMM thread's exclusive borrow of the VM, under which
    /// a capture is armed, sent and waited for. No capture can then be in
    /// flight while the handler changes the registration, and no
    /// capture-done message can be taken for the verdict.
    ///
    /// A handler that does not know the settle message ends the session
    /// instead of answering, which fails this call and, through the hangup
    /// watch, the VM.
    pub(crate) fn settle(&mut self) -> io::Result<bool> {
        if !self.demand_paged() {
            return Ok(true);
        }
        let body = serde_json::to_vec(&Settle {
            version: SETTLE_VERSION,
        })?;
        {
            let _write = self
                .write
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            send_message(&self.stream, MSG_SETTLE, &body, &[])?;
        }
        let verdict = receive_message(&self.stream, MSG_SETTLE_VERDICT).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("the fault handler did not answer the settle: {error}"),
            )
        })?;
        match serde_json::from_slice(&verdict)? {
            SettleVerdict::Settled => {
                self.mode = RegistrationMode::WriteProtectOnly;
                Ok(true)
            }
            SettleVerdict::NotYet => Ok(false),
            SettleVerdict::Refused { error } => Err(io::Error::other(format!(
                "the fault handler refused to settle guest RAM: {error}"
            ))),
        }
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
        let mut body = CaptureBody::default();
        if let Err(error) = serde_json::to_writer(&mut body, &Capture { ranges }) {
            return Err(if body.over_bound {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "a capture body exceeds the {MAX_CAPTURE_BODY_LEN} the fault handler reads"
                    ),
                )
            } else {
                error.into()
            });
        }
        let _write = self
            .write
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        send_message(&self.stream, MSG_CAPTURE, &body.bytes, &[out.as_raw_fd()])
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
        let body = receive_message(stream, MSG_CAPTURE_DONE)?;
        match serde_json::from_slice(&body)? {
            CaptureOutcome::Success => Ok(Ok(())),
            CaptureOutcome::Failure { error } => Ok(Err(error)),
        }
    }
}

/// Relays the userfaultfds of vhost-user backends to a demand-paged VM's
/// fault handler, over the VM's fault session.
pub(crate) struct BackendFaultRelay {
    stream: UnixStream,
    write: Arc<Mutex<()>>,
    /// Marks the relay as held, for [`FaultSession::relays_backends`].
    _session: Arc<()>,
}

impl BackendFaultHandler for BackendFaultRelay {
    fn adopt(
        &self,
        device: &str,
        connection: u64,
        mappings: &[BackendMapping],
        uffd: Option<BorrowedFd<'_>>,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(&BackendHandoff {
            device: device.to_owned(),
            connection,
            regions: mappings
                .iter()
                .map(|mapping| BackendRegion {
                    backend_addr: mapping.backend_addr,
                    vmm_addr: mapping.vmm_addr,
                    length: mapping.length,
                    page_size: mapping.page_size,
                })
                .collect(),
        })?;
        let (verdict, handler_end) = UnixStream::pair()?;
        let mut fds = vec![handler_end.as_raw_fd()];
        fds.extend(uffd.map(|uffd| uffd.as_raw_fd()));
        {
            let _write = self
                .write
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            send_message(&self.stream, MSG_BACKEND_HANDOFF, &body, &fds)?;
        }
        // Only the handler holds the other end now, so the read below ends
        // with an error rather than blocking forever if the handler goes
        // away without answering.
        drop(handler_end);
        match serde_json::from_slice(&receive_message(&verdict, MSG_BACKEND_VERDICT)?)? {
            BackendVerdict::Adopted => Ok(()),
            BackendVerdict::Rejected { error } => Err(io::Error::other(format!(
                "the fault handler refused the memory table of {device}'s backend: {error}"
            ))),
        }
    }
}

/// Watches a fault session's connection for the fault handler hanging up.
///
/// The handler owns every fault on guest RAM. Once it is gone, a vCPU that
/// touches a missing or write-protected page sleeps in the kernel until a
/// fatal signal, so the VM can neither run nor shut down. On a hangup the
/// watch logs it, records [`SESSION_LOST`] where the VMM was asked to record
/// why it exits, and ends the process: the VMM can no longer run the VM, and
/// its manager reads the recorded reason — that the fault session was lost,
/// not that the VMM crashed — as a VM failure to report rather than as a
/// checkpoint to rewind to.
///
/// Only `POLLRDHUP` is polled for, so capture-done messages stay queued for
/// [`FaultSession::wait_done`].
struct HangupWatch {
    stop: EventFd,
    thread: Option<JoinHandle<()>>,
}

impl HangupWatch {
    /// Start watching `stream`, a clone of the session's connection, and
    /// record [`SESSION_LOST`] at `exit_reason` should it hang up.
    fn spawn(stream: UnixStream, exit_reason: Option<&Path>) -> io::Result<Self> {
        let stop = EventFd::new(0)?;
        let stopped = stop.try_clone()?;
        let exit_reason: Option<PathBuf> = exit_reason.map(Path::to_path_buf);
        let thread = Builder::new()
            .name("fault_hangup".to_string())
            .spawn(move || Self::watch(&stream, &stopped, exit_reason.as_deref()))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Block until `stop` is signalled, returning, or the peer hangs up,
    /// ending the process.
    fn watch(stream: &UnixStream, stop: &EventFd, exit_reason: Option<&Path>) {
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
                Self::exit(exit_reason);
            }
            if fds[1].revents != 0 {
                return;
            }
            if fds[0].revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0 {
                error!(
                    "the fault handler closed the VM's fault session; guest memory can no longer be served"
                );
                Self::exit(exit_reason);
            }
        }
    }

    /// Record why the VMM is exiting, at the path it was given when it has
    /// one, then end the process, flushing the log first. The record is whole
    /// before the process ends, and its reader is the manager settling the
    /// exit, which only looks once the process is gone: no reader can see a
    /// partial one. A failure to write is logged: the VMM exits either way,
    /// and a missing reason reads as an exit with no reason given.
    fn exit(exit_reason: Option<&Path>) -> ! {
        if let Some(path) = exit_reason
            && let Err(error) = fs::write(path, SESSION_LOST)
        {
            error!("recording the exit reason at {}: {error}", path.display());
        }
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

/// A capture body as it is serialised, refusing to grow past
/// [`MAX_CAPTURE_BODY_LEN`]. An over-bound body is refused where it crosses the
/// bound rather than once the whole frame is built, so the VMM never holds one
/// the fault handler would refuse unread.
#[derive(Default)]
struct CaptureBody {
    bytes: Vec<u8>,
    /// The serialisation was cut short for its size, not for another failure.
    over_bound: bool,
}

impl io::Write for CaptureBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len() + bytes.len() > MAX_CAPTURE_BODY_LEN {
            self.over_bound = true;
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    // The rest of a body a signal cut short goes through sendmsg too, with no
    // descriptors: the vhost-user worker threads that relay backend handoffs
    // on reconnect are allowed sendmsg, not every other send.
    let mut sent = sent - HEADER_LEN;
    while sent < body.len() {
        match stream.send_with_fds(&[&body[sent..]], &[]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the fault-handler connection accepted no more of a message",
                ));
            }
            Ok(more) => sent += more,
            Err(e) if e.errno() == libc::EINTR => {}
            Err(e) => {
                return Err(io::Error::other(format!(
                    "sendmsg to the fault handler: {e}"
                )));
            }
        }
    }
    Ok(())
}

/// Read one message from the fault handler on `stream`, blocking, and
/// return its body, which must be of type `expected`.
fn receive_message(stream: &UnixStream, expected: u32) -> io::Result<Vec<u8>> {
    // Read through recvmsg, which every thread that waits on the handler
    // (the vmm thread, and the vhost-user workers on reconnect) is allowed,
    // unlike the recvfrom a plain read of a socket makes.
    let read_exact = |buf: &mut [u8]| -> io::Result<()> {
        let mut read = 0;
        while read < buf.len() {
            match stream.recv_with_fd(&mut buf[read..]) {
                Ok((0, _)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the fault handler closed the connection mid-message",
                    ));
                }
                Ok((more, _)) => read += more,
                Err(e) if e.errno() == libc::EINTR => {}
                Err(e) => {
                    return Err(io::Error::other(format!(
                        "recvmsg from the fault handler: {e}"
                    )));
                }
            }
        }
        Ok(())
    };
    let mut header = [0u8; HEADER_LEN];
    read_exact(&mut header)?;
    let message_type = u32::from_le_bytes(header[0..4].try_into().expect("4-byte slice"));
    let body_len = u32::from_le_bytes(header[4..8].try_into().expect("4-byte slice"));
    if message_type != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected message type {message_type} from the fault handler"),
        ));
    }
    if body_len > MAX_RECEIVED_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message body of {body_len} bytes from the fault handler exceeds the bound"),
        ));
    }
    let mut body = vec![0u8; body_len as usize];
    read_exact(&mut body)?;
    Ok(body)
}

/// Test support: the fault handler's side of the settle exchange.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Queue the verdict that guest RAM is settled on `handler`, the fault
    /// handler's end of a session, for the session's next settle to read.
    pub(crate) fn queue_settled(handler: &UnixStream) {
        let body = serde_json::to_vec(&SettleVerdict::Settled).unwrap();
        send_message(handler, MSG_SETTLE_VERDICT, &body, &[]).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    /// A demand-paged fault session and the stand-in handler's end of its
    /// connection, the handoff already read off it. The handler's end comes
    /// first so that it is dropped last: the session's hang-up watch, which
    /// ends the process, never sees it go.
    fn demand_paged_session() -> (UnixStream, FaultSession) {
        let dir = TempDir::new_with_prefix("/tmp/fault-session-").unwrap();
        let socket = dir.as_path().join("fault.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let session = FaultSession::establish(
            &socket,
            RegistrationMode::MissingAndWriteProtect,
            Vec::new(),
            OwnedFd::from(tempfile::tempfile().unwrap()),
            &[],
            None,
        )
        .unwrap();
        let handler = listener.accept().unwrap().0;
        receive_message(&handler, MSG_HANDOFF).unwrap();
        (handler, session)
    }

    /// Queue `verdict` on the handler's end, for the session's next settle.
    fn queue_verdict(handler: &UnixStream, verdict: &SettleVerdict) {
        let body = serde_json::to_vec(verdict).unwrap();
        send_message(handler, MSG_SETTLE_VERDICT, &body, &[]).unwrap();
    }

    /// Whether a message from the session waits on the handler's end.
    fn message_waits(handler: &UnixStream) -> bool {
        let mut fd = libc::pollfd {
            fd: handler.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polling one initialized pollfd whose descriptor is open.
        let ready = unsafe { libc::poll(&mut fd, 1, 0) };
        assert!(ready >= 0);
        ready == 1
    }

    /// A settled verdict makes the session a booted VM's: no longer
    /// demand-paged, with no relay to hand out. The settle names the version
    /// the VMM speaks, and a later settle answers without asking again.
    #[test]
    fn a_settled_verdict_ends_demand_paging() {
        let (handler, mut session) = demand_paged_session();
        queue_verdict(&handler, &SettleVerdict::Settled);

        assert!(session.settle().unwrap());

        let settle: Settle =
            serde_json::from_slice(&receive_message(&handler, MSG_SETTLE).unwrap()).unwrap();
        assert_eq!(settle.version, SETTLE_VERSION);
        assert!(!session.demand_paged());
        assert!(session.backend_fault_relay().unwrap().is_none());

        assert!(session.settle().unwrap());
        assert!(!message_waits(&handler));
    }

    /// While the handler is still serving the image the settle changes
    /// nothing: guest RAM stays demand-paged and backends are still relayed.
    #[test]
    fn a_not_yet_verdict_changes_nothing() {
        let (handler, mut session) = demand_paged_session();
        queue_verdict(&handler, &SettleVerdict::NotYet);

        assert!(!session.settle().unwrap());

        assert!(session.demand_paged());
        assert!(session.backend_fault_relay().unwrap().is_some());
    }

    /// A handler that refuses the settle, as one speaking another version of
    /// the exchange does, fails it with the handler's reason and changes
    /// nothing.
    #[test]
    fn a_refused_settle_fails_with_the_handlers_reason() {
        let (handler, mut session) = demand_paged_session();
        queue_verdict(
            &handler,
            &SettleVerdict::Refused {
                error: "settle version 1 is not spoken here".to_string(),
            },
        );

        let error = session.settle().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("settle version 1 is not spoken here"),
            "{error}"
        );
        assert!(session.demand_paged());
    }

    /// An answer that is not a settle verdict this VMM knows fails the
    /// settle rather than being taken for one: another message's type, or a
    /// verdict of a shape from another version.
    #[test]
    fn an_answer_that_is_no_known_verdict_fails_the_settle() {
        let (handler, mut session) = demand_paged_session();
        let done = serde_json::to_vec(&CaptureOutcome::Success).unwrap();
        send_message(&handler, MSG_CAPTURE_DONE, &done, &[]).unwrap();
        let error = session.settle().unwrap_err();
        assert!(
            error.to_string().contains("unexpected message type 3"),
            "{error}"
        );

        send_message(&handler, MSG_SETTLE_VERDICT, br#""Deferred""#, &[]).unwrap();
        let error = session.settle().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(session.demand_paged());
    }

    /// The session knows whether a relay it handed out is still held.
    #[test]
    fn a_held_relay_is_counted() {
        let (_handler, session) = demand_paged_session();
        assert!(!session.relays_backends());

        let relay = session.backend_fault_relay().unwrap().unwrap();
        assert!(session.relays_backends());

        drop(relay);
        assert!(!session.relays_backends());
    }
}
