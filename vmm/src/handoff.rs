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
//!
//! A demand-paged handoff can explicitly request a `WorksetInstalled`
//! receipt (type 8). It must be the peer's first and only startup frame
//! and list only template working-set pages it has already installed. The
//! peer sends an empty receipt for a non-template restore.

use std::fs::{self, File};
use std::mem::zeroed;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};
use std::{io, process};

use log::error;
use serde::{Deserialize, Serialize};
use virtio_devices::vhost_user::{
    BackendFaultHandler, BackendFaults, BackendMapping, DemandPaging, SettleError,
};
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
/// Header discriminant of an installed working-set receipt.
const MSG_WORKSET_INSTALLED: u32 = 8;

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

const MAX_WORKSET_BODY_LEN: u32 = 512 * 1024;
const MAX_WORKSET_PAGES: u64 = 8192;
const WORKSET_PAGE_SIZE: u64 = 4096;
const WORKSET_RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes of a capture body the fault handler reads, mirroring its own
/// bound (`crucible-pageserver`'s `protocol::MAX_BODY_LEN`, the wire
/// contract's authority). A capture's body is its armed ranges as JSON, which
/// a fragmented dirty set of the platform's largest VM brings to 964 MB. A
/// body past the bound is refused here, failing that one checkpoint with a
/// reason: sending it would end the session, which the VM cannot survive.
const MAX_CAPTURE_BODY_LEN: usize = 1 << 30;

/// How long the fault handler has to answer a settle.
///
/// A settle has the handler install nothing: it reads the faults already
/// raised, takes each vhost-user backend's mappings off its userfaultfd and
/// registers guest RAM again. That was measured at two to three
/// milliseconds on an idle host, and at some tens of milliseconds for each
/// of 48 VMs restored at once on 24 hardware threads. The deadline is a
/// hundred times the slowest of those, so that only a handler that is not
/// going to answer runs into it, and short enough that the VMM thread,
/// which waits for the verdict with the VM borrowed, is not kept from
/// every other request for long.
const SETTLE_DEADLINE: Duration = Duration::from_secs(5);

/// The reason the VMM records when it exits because its fault session is
/// gone, or because a vhost-user backend did not leave it at the settle.
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    report_installed: bool,
}

impl Handoff {
    /// Bind the receipt to this handoff's own, disjoint host/GPA mappings.
    fn workset_layout(&self, gpas: &[u64]) -> io::Result<Vec<(u64, &HandoffRegion)>> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid working-set handoff layout",
            )
        };
        if self.mode != RegistrationMode::MissingAndWriteProtect || gpas.len() != self.regions.len()
        {
            return Err(invalid());
        }
        let mut layout = Vec::with_capacity(gpas.len());
        for (&gpa, region) in gpas.iter().zip(&self.regions) {
            if region.length == 0
                || !gpa.is_multiple_of(WORKSET_PAGE_SIZE)
                || !region.length.is_multiple_of(WORKSET_PAGE_SIZE)
                || !region.vmm_addr.is_multiple_of(WORKSET_PAGE_SIZE)
                || region.vmm_addr.checked_add(region.length).is_none()
                || gpa.checked_add(region.length).is_none()
            {
                return Err(invalid());
            }
            layout.push((gpa, region));
        }
        layout.sort_unstable_by_key(|(gpa, _)| *gpa);
        if layout
            .windows(2)
            .any(|pair| pair[0].0 + pair[0].1.length > pair[1].0)
        {
            return Err(invalid());
        }
        layout.sort_unstable_by_key(|(_, region)| region.vmm_addr);
        if layout.windows(2).any(|pair| {
            let (_, first) = pair[0];
            let (_, second) = pair[1];
            first.vmm_addr + first.length > second.vmm_addr
        }) {
            return Err(invalid());
        }
        Ok(layout)
    }
}

/// Installed bytes in the VMM's virtual address space.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledRange {
    vmm_addr: u64,
    length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorksetInstalled {
    ranges: Vec<InstalledRange>,
}

/// The one startup receipt, consumed before the restored vCPUs can run.
pub(crate) struct InstalledWorkset {
    pub(crate) gpa_ranges: Vec<(u64, u64)>,
    pub(crate) bytes: u64,
    pub(crate) receipt_time: Duration,
}

impl WorksetInstalled {
    /// Translate only whole, aligned, non-overlapping ranges within the
    /// exact 4 KiB-backed registrations sent in the handoff.
    fn into_guest_ranges(
        mut self,
        regions: &[(u64, &HandoffRegion)],
        receipt_started: Instant,
    ) -> io::Result<InstalledWorkset> {
        let invalid = |reason| io::Error::new(io::ErrorKind::InvalidData, reason);
        if self.ranges.len() > MAX_WORKSET_PAGES as usize {
            return Err(invalid("too many installed working-set ranges"));
        }
        self.ranges.sort_unstable_by_key(|range| range.vmm_addr);
        let mut previous_end = 0;
        let mut bytes = 0u64;
        let mut regions = regions.iter().peekable();
        let mut gpa_ranges = Vec::with_capacity(self.ranges.len());
        for range in self.ranges {
            let end = range
                .vmm_addr
                .checked_add(range.length)
                .filter(|_| {
                    range.vmm_addr >= previous_end
                        && range.length != 0
                        && range.vmm_addr.is_multiple_of(WORKSET_PAGE_SIZE)
                        && range.length.is_multiple_of(WORKSET_PAGE_SIZE)
                })
                .ok_or_else(|| invalid("invalid installed working-set range"))?;
            bytes = bytes
                .checked_add(range.length)
                .filter(|&bytes| bytes <= MAX_WORKSET_PAGES * WORKSET_PAGE_SIZE)
                .ok_or_else(|| invalid("installed working set exceeds the page limit"))?;
            while regions
                .peek()
                .is_some_and(|(_, region)| region.vmm_addr + region.length <= range.vmm_addr)
            {
                regions.next();
            }
            let (gpa, region) = regions
                .peek()
                .filter(|(_, region)| {
                    region.page_size == WORKSET_PAGE_SIZE
                        && range.vmm_addr >= region.vmm_addr
                        && end <= region.vmm_addr + region.length
                })
                .ok_or_else(|| {
                    invalid("installed working-set range is outside its registration")
                })?;
            gpa_ranges.push((gpa + (range.vmm_addr - region.vmm_addr), range.length));
            previous_end = end;
        }
        Ok(InstalledWorkset {
            gpa_ranges,
            bytes,
            receipt_time: receipt_started.elapsed(),
        })
    }
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
    installed_workset: Option<InstalledWorkset>,
    /// Serializes whole messages onto the connection: captures are sent from
    /// here, and backend handoffs from the [`BackendFaultRelay`]s of
    /// vhost-user devices, which can connect at any time.
    write: Arc<Mutex<()>>,
    /// Whether guest RAM is still demand-paged, as the vhost-user devices
    /// handed a relay see it: settled by [`Self::settle`], with no memory
    /// table in flight. A write-protect-only session hands out no relay, so
    /// no device reads it.
    paging: Arc<DemandPaging>,
    /// Where the VMM records why it exits, for a session lost over a
    /// failed exchange.
    exit_reason: Option<PathBuf>,
}

impl FaultSession {
    /// Connect to the fault handler listening on `socket` and hand it the
    /// registered userfaultfd with the guest-RAM layout. `memfds` are the
    /// files backing the regions, in the order `HandoffRegion::memfd`
    /// indexes. `exit_reason` is where the VMM records why it exits, which
    /// is written before the process ends over a lost session, whether the
    /// hangup watch or a failed exchange found it lost.
    pub(crate) fn establish(
        socket: &Path,
        mode: RegistrationMode,
        regions: Vec<HandoffRegion>,
        uffd: OwnedFd,
        memfds: &[RawFd],
        exit_reason: Option<&Path>,
        report_installed_for_gpas: Option<&[u64]>,
    ) -> io::Result<Self> {
        let handoff = Handoff {
            mode,
            regions,
            report_installed: report_installed_for_gpas.is_some(),
        };
        let workset_layout = report_installed_for_gpas
            .map(|gpas| handoff.workset_layout(gpas))
            .transpose()?;
        let stream = UnixStream::connect(socket)?;
        let body = serde_json::to_vec(&handoff)?;
        let mut fds = Vec::with_capacity(memfds.len() + 1);
        fds.push(uffd.as_raw_fd());
        fds.extend_from_slice(memfds);
        send_message(&stream, MSG_HANDOFF, &body, &fds)?;
        let installed_workset = if let Some(layout) = workset_layout {
            let started = Instant::now();
            let body = receive_message(
                &stream,
                MSG_WORKSET_INSTALLED,
                Some(started + WORKSET_RECEIPT_TIMEOUT),
            )?;
            let receipt: WorksetInstalled = serde_json::from_slice(&body).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid installed working-set receipt",
                )
            })?;
            let workset = receipt.into_guest_ranges(&layout, started)?;
            Self::check_startup_stream(&stream)?;
            Some(workset)
        } else {
            None
        };
        let hangup = HangupWatch::spawn(stream.try_clone()?, exit_reason)?;
        Ok(Self {
            _hangup: hangup,
            stream,
            uffd,
            mode,
            installed_workset,
            write: Arc::new(Mutex::new(())),
            paging: Arc::new(DemandPaging::default()),
            exit_reason: exit_reason.map(Path::to_path_buf),
        })
    }

    /// Take the receipt once. Later readers still require the message type
    /// for their own exchange, so a delayed second receipt cannot be used.
    pub(crate) fn take_installed_workset(&mut self) -> Option<InstalledWorkset> {
        self.installed_workset.take()
    }

    /// No second frame (or disconnect) is permitted before the restore
    /// starts the vCPUs. Check queued input without waiting for future bytes.
    pub(crate) fn check_workset_stream(&self) -> io::Result<()> {
        Self::check_startup_stream(&self.stream)
    }

    fn check_startup_stream(stream: &UnixStream) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polling one initialized pollfd whose descriptor stays open.
        match unsafe { libc::poll(&mut fd, 1, 0) } {
            0 => Ok(()),
            -1 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected input or disconnect after the installed working-set receipt",
            )),
        }
    }

    /// Whether guest RAM is demand-paged through this session, as opposed to
    /// only write-protected for captures.
    pub(crate) fn demand_paged(&self) -> bool {
        self.mode == RegistrationMode::MissingAndWriteProtect
    }

    /// How the backend of vhost-user device `device` serves faults, when
    /// guest RAM is demand-paged through this session: through a relay of
    /// its userfaultfds to the fault handler, until the settle ends the
    /// postcopy flow. `None` for a write-protect-only session, whose guest
    /// RAM has nothing to serve, a settled one included.
    pub(crate) fn backend_faults(&self, device: &str) -> io::Result<Option<BackendFaults>> {
        if !self.demand_paged() {
            return Ok(None);
        }
        Ok(Some(BackendFaults {
            device: device.to_owned(),
            handler: Arc::new(BackendFaultRelay {
                stream: self.stream.try_clone()?,
                write: Arc::clone(&self.write),
            }),
            paging: Arc::clone(&self.paging),
        }))
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
    /// The exchange runs with no vhost-user memory table in flight (see
    /// [`DemandPaging`]): no backend maps guest RAM afresh while the handler
    /// takes the backends' mappings off their userfaultfds. A settled
    /// verdict then ends the postcopy flow on every backend connection on
    /// it before the settle is recorded, so no backend is registered for
    /// missing faults once this returns `true`, and each table sent after is
    /// a plain one.
    ///
    /// A handler that refuses the settle fails this call, and nothing has
    /// changed. An exchange that fails any other way is the loss of the
    /// session (see [`Self::exchange_settle`]): the VMM records that and
    /// exits, as it does when the handler hangs up, which is also how a
    /// handler that does not know the settle message answers one. So is a
    /// backend that does not end its postcopy flow once the handler has
    /// settled: it may still be registered for missing faults on guest RAM
    /// the handler no longer serves, and a device left to it could lose its
    /// disk with the guest none the wiser.
    pub(crate) fn settle(&mut self) -> io::Result<bool> {
        if !self.demand_paged() {
            return Ok(true);
        }
        let settled = Arc::clone(&self.paging).settle(|| {
            match self.exchange_settle(SETTLE_DEADLINE) {
                Ok(SettleVerdict::Settled) => Ok(true),
                Ok(SettleVerdict::NotYet) => Ok(false),
                Ok(SettleVerdict::Refused { error }) => Err(io::Error::other(format!(
                    "the fault handler refused to settle guest RAM: {error}"
                ))),
                Err(error) => {
                    error!(
                        "the settle exchange with the fault handler failed, and the VM's fault session with it: {error}"
                    );
                    HangupWatch::exit(self.exit_reason.as_deref())
                }
            }
        });
        let settled = match settled {
            Ok(settled) => settled,
            Err(SettleError::Exchange(error)) => return Err(error),
            Err(SettleError::EndRefused { connection, error }) => {
                error!(
                    "the backend of vhost-user connection {connection} did not end its postcopy flow once guest RAM settled, and may still wait on faults nothing serves: {error:?}"
                );
                HangupWatch::exit(self.exit_reason.as_deref())
            }
        };
        if settled {
            self.mode = RegistrationMode::WriteProtectOnly;
        }
        Ok(settled)
    }

    /// Send a settle and read the handler's verdict, which has `deadline`
    /// to arrive.
    ///
    /// An error leaves the connection in no known state: a verdict that
    /// arrives late, or the rest of a message read in part, would be taken
    /// for the answer to the next settle or capture. So no error here can
    /// be survived by the session: a verdict that did not arrive in time, a
    /// message of another type or of no shape this VMM knows, or a failure
    /// of the connection itself.
    fn exchange_settle(&self, deadline: Duration) -> io::Result<SettleVerdict> {
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
        let verdict = receive_message(
            &self.stream,
            MSG_SETTLE_VERDICT,
            Some(Instant::now() + deadline),
        )?;
        Ok(serde_json::from_slice(&verdict)?)
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
        let body = receive_message(stream, MSG_CAPTURE_DONE, None)?;
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
        match serde_json::from_slice(&receive_message(&verdict, MSG_BACKEND_VERDICT, None)?)? {
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
    ///
    /// The watch and a failed exchange can both find the session lost at
    /// once: a handler that closes the connection on a settle it does not
    /// know fails the exchange as the watch sees the hangup. Only the first
    /// to get here records and exits; the second waits here for the process
    /// to end. Two at once would each truncate the record as they write it,
    /// and the first to exit could leave it empty.
    fn exit(exit_reason: Option<&Path>) -> ! {
        static EXITING: Mutex<()> = Mutex::new(());
        let _exiting = EXITING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
/// return its body, which must be of type `expected`. With a `deadline`
/// the whole message must have arrived by then, or the read fails as timed
/// out; only the vmm thread may give one, since it is waited for with a
/// poll, which the vhost-user workers are not allowed.
fn receive_message(
    stream: &UnixStream,
    expected: u32,
    deadline: Option<Instant>,
) -> io::Result<Vec<u8>> {
    let strict = expected == MSG_WORKSET_INSTALLED;
    let timed_out = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the fault handler did not send its message in time",
        )
    };
    // Read through recvmsg, which every thread that waits on the handler
    // (the vmm thread, and the vhost-user workers on reconnect) is allowed,
    // unlike the recvfrom a plain read of a socket makes.
    let read_exact = |buf: &mut [u8]| -> io::Result<()> {
        let mut read = 0;
        while read < buf.len() {
            if let Some(deadline) = deadline {
                // Whole milliseconds, rounded up: the wait never ends
                // before the deadline.
                let left = deadline.saturating_duration_since(Instant::now());
                if strict && left.is_zero() {
                    return Err(timed_out());
                }
                let left = left.as_nanos().div_ceil(1_000_000);
                let mut fd = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: polling one initialized pollfd whose descriptor
                // stays open for the duration of the call.
                let ready =
                    unsafe { libc::poll(&mut fd, 1, i32::try_from(left).unwrap_or(i32::MAX)) };
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if ready == 0 {
                    return Err(timed_out());
                }
            }
            let received = if strict {
                receive_workset_bytes(stream, &mut buf[read..])
            } else {
                stream
                    .recv_with_fd(&mut buf[read..])
                    .map(|(len, _)| len)
                    .map_err(|error| {
                        if error.errno() == libc::EINTR {
                            io::Error::from(io::ErrorKind::Interrupted)
                        } else {
                            io::Error::other(format!("recvmsg from the fault handler: {error}"))
                        }
                    })
            };
            match received {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the fault handler closed the connection mid-message",
                    ));
                }
                Ok(more) => read += more,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if strict && e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
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
    let max = if strict {
        MAX_WORKSET_BODY_LEN
    } else {
        MAX_RECEIVED_LEN
    };
    if body_len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message body of {body_len} bytes from the fault handler exceeds the bound"),
        ));
    }
    let mut body = vec![0u8; body_len as usize];
    read_exact(&mut body)?;
    if strict && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(timed_out());
    }
    Ok(body)
}

/// Receive data without a control buffer. Linux drops SCM_RIGHTS instead
/// of installing descriptors and marks the message truncated when
/// ancillary data was present. Nonblocking recv cannot overrun the poll
/// deadline, and unlike changing O_NONBLOCK affects only this call.
fn receive_workset_bytes(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: null pointers and zero lengths denote absent name and control buffers.
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: msg points to a live iovec over the caller's writable buffer.
    let read = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_DONTWAIT) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated data or unexpected descriptors in the working-set receipt",
        ));
    }
    Ok(read as usize)
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
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    fn workset_region(vmm_addr: u64, length: u64, page_size: u64) -> HandoffRegion {
        HandoffRegion {
            vmm_addr,
            length,
            source_offset: 0,
            page_size,
            memfd: 0,
            memfd_offset: 0,
        }
    }

    #[test]
    fn workset_receipt_translates_only_whole_backed_ranges() {
        let handoff = Handoff {
            mode: RegistrationMode::MissingAndWriteProtect,
            regions: vec![
                workset_region(0x8000, 0x4000, 4096),
                workset_region(0x4000, 0x2000, 4096),
                workset_region(0x6000, 0x1000, 8192),
            ],
            report_installed: true,
        };
        for gpas in [
            &[0, 0x1000, 0x20000][..],
            &[0, 0x10000],
            &[u64::MAX - 0xfff, 0x10000, 0x20000],
        ] {
            assert_eq!(
                handoff.workset_layout(gpas).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let layout = handoff.workset_layout(&[0, 0x10000, 0x20000]).unwrap();
        let receipt = |ranges: &[(u64, u64)]| {
            WorksetInstalled {
                ranges: ranges
                    .iter()
                    .map(|&(vmm_addr, length)| InstalledRange { vmm_addr, length })
                    .collect(),
            }
            .into_guest_ranges(&layout, Instant::now())
        };
        let installed = receipt(&[(0x9000, 0x2000), (0x5000, 0x1000)]).unwrap();
        assert_eq!(installed.gpa_ranges, [(0x11000, 0x1000), (0x1000, 0x2000)]);
        assert_eq!(installed.bytes, 0x3000);
        assert_eq!(receipt(&[]).unwrap().bytes, 0);
        for ranges in [
            &[(0x4000, 0)][..],
            &[(0x4001, 0x1000)],
            &[(0x4000, 0x1001)],
            &[(0x5000, 0x2000)],
            &[(0x6000, 0x1000)],
            &[(0x7000, 0x1000)],
            &[(0x8000, 0x2000), (0x9000, 0x1000)],
            &[(u64::MAX - 0xfff, 0x1000)],
        ] {
            assert!(matches!(receipt(ranges), Err(e) if e.kind() == io::ErrorKind::InvalidData));
        }
    }

    #[test]
    fn workset_receipt_caps_both_range_count_and_total_pages() {
        let base = 0x100000000;
        let byte_limit = MAX_WORKSET_PAGES * WORKSET_PAGE_SIZE;
        let handoff = Handoff {
            mode: RegistrationMode::MissingAndWriteProtect,
            regions: vec![workset_region(base, byte_limit * 2, WORKSET_PAGE_SIZE)],
            report_installed: true,
        };
        let layout = handoff.workset_layout(&[0]).unwrap();
        let pages = |count| WorksetInstalled {
            ranges: (0..count)
                .map(|page| InstalledRange {
                    vmm_addr: base + page * WORKSET_PAGE_SIZE,
                    length: WORKSET_PAGE_SIZE,
                })
                .collect(),
        };
        assert_eq!(
            pages(MAX_WORKSET_PAGES)
                .into_guest_ranges(&layout, Instant::now())
                .unwrap()
                .bytes,
            byte_limit
        );
        assert!(
            pages(MAX_WORKSET_PAGES + 1)
                .into_guest_ranges(&layout, Instant::now())
                .is_err()
        );
        assert!(
            WorksetInstalled {
                ranges: vec![InstalledRange {
                    vmm_addr: base,
                    length: byte_limit + WORKSET_PAGE_SIZE,
                }],
            }
            .into_guest_ranges(&layout, Instant::now())
            .is_err()
        );
    }

    #[test]
    fn workset_frames_refuse_wrong_type_oversize_or_ancillary_data() {
        let body = br#"{"ranges":[]}"#;
        let deadline = Instant::now() + Duration::from_secs(1);
        let file = tempfile::tempfile().unwrap();
        let raw = file.as_raw_fd();
        let full_header = [
            &MSG_WORKSET_INSTALLED.to_le_bytes()[..],
            &(body.len() as u32).to_le_bytes(),
        ]
        .concat();
        let (ours, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&MSG_WORKSET_INSTALLED.to_le_bytes())
            .unwrap();
        peer.write_all(&(MAX_WORKSET_BODY_LEN + 1).to_le_bytes())
            .unwrap();
        assert_eq!(
            receive_message(&ours, MSG_WORKSET_INSTALLED, Some(deadline))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        for fds in [&[][..], &[raw], &[raw, raw, raw, raw]] {
            let (ours, mut peer) = UnixStream::pair().unwrap();
            if fds.is_empty() {
                send_message(&peer, MSG_SETTLE_VERDICT, body, fds).unwrap();
            } else {
                peer.write_all(&full_header).unwrap();
                assert_eq!(peer.send_with_fds(&[&body[..]], fds).unwrap(), body.len());
            }
            assert_eq!(
                receive_message(&ours, MSG_WORKSET_INSTALLED, Some(deadline))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn workset_frames_require_a_complete_message_before_the_deadline() {
        let body = br#"{"ranges":[]}"#;
        let (ours, peer) = UnixStream::pair().unwrap();
        send_message(&peer, MSG_WORKSET_INSTALLED, body, &[]).unwrap();
        assert_eq!(
            receive_message(&ours, MSG_WORKSET_INSTALLED, Some(Instant::now()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            receive_message(
                &ours,
                MSG_WORKSET_INSTALLED,
                Some(Instant::now() + Duration::from_secs(1))
            )
            .unwrap(),
            body
        );
        for partial_body in [false, true] {
            let (ours, mut peer) = UnixStream::pair().unwrap();
            peer.write_all(&MSG_WORKSET_INSTALLED.to_le_bytes())
                .unwrap();
            if partial_body {
                peer.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
                peer.write_all(&body[..5]).unwrap();
            }
            assert_eq!(
                receive_message(
                    &ours,
                    MSG_WORKSET_INSTALLED,
                    Some(Instant::now() + Duration::from_millis(10))
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::TimedOut
            );
        }
        let (ours, peer) = UnixStream::pair().unwrap();
        drop(peer);
        assert_eq!(
            receive_message(
                &ours,
                MSG_WORKSET_INSTALLED,
                Some(Instant::now() + Duration::from_secs(1))
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn opted_in_session_takes_one_empty_receipt_and_rejects_a_later_frame() {
        let dir = TempDir::new_with_prefix("/tmp/fault-session-workset-").unwrap();
        let socket = dir.as_path().join("fault.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let body = br#"{"ranges":[]}"#;
        let server = thread::spawn(move || {
            let peer = listener.accept().unwrap().0;
            let handoff: Handoff =
                serde_json::from_slice(&receive_message(&peer, MSG_HANDOFF, None).unwrap())
                    .unwrap();
            assert!(handoff.report_installed);
            send_message(&peer, MSG_WORKSET_INSTALLED, body, &[]).unwrap();
            peer
        });
        let mut session = FaultSession::establish(
            &socket,
            RegistrationMode::MissingAndWriteProtect,
            Vec::new(),
            OwnedFd::from(tempfile::tempfile().unwrap()),
            &[],
            None,
            Some(&[]),
        )
        .unwrap();
        let peer = server.join().unwrap();
        assert!(
            session
                .take_installed_workset()
                .unwrap()
                .gpa_ranges
                .is_empty()
        );
        assert!(session.take_installed_workset().is_none());
        session.check_workset_stream().unwrap();
        send_message(&peer, MSG_WORKSET_INSTALLED, body, &[]).unwrap();
        assert!(session.check_workset_stream().is_err());
        assert_eq!(
            FaultSession::wait_done(&session.stream).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(session);
    }

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
            None,
        )
        .unwrap();
        let handler = listener.accept().unwrap().0;
        let handoff: serde_json::Value =
            serde_json::from_slice(&receive_message(&handler, MSG_HANDOFF, None).unwrap()).unwrap();
        assert!(handoff.get("report_installed").is_none());
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
        let faults = session.backend_faults("_disk0").unwrap().unwrap();
        queue_verdict(&handler, &SettleVerdict::Settled);

        assert!(session.settle().unwrap());
        assert!(faults.paging.settled());

        let settle: Settle =
            serde_json::from_slice(&receive_message(&handler, MSG_SETTLE, None).unwrap()).unwrap();
        assert_eq!(settle.version, SETTLE_VERSION);
        assert!(!session.demand_paged());
        assert!(session.backend_faults("_disk1").unwrap().is_none());

        assert!(session.settle().unwrap());
        assert!(!message_waits(&handler));
    }

    /// While the handler is still serving the image the settle changes
    /// nothing: guest RAM stays demand-paged and backends are still relayed.
    #[test]
    fn a_not_yet_verdict_changes_nothing() {
        let (handler, mut session) = demand_paged_session();
        let faults = session.backend_faults("_disk0").unwrap().unwrap();
        queue_verdict(&handler, &SettleVerdict::NotYet);

        assert!(!session.settle().unwrap());

        assert!(session.demand_paged());
        assert!(!faults.paging.settled());
        assert!(session.backend_faults("_disk1").unwrap().is_some());
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

    /// How long the exchanges below give a stand-in handler that answers
    /// at once, or never.
    const A_MOMENT: Duration = Duration::from_millis(200);

    /// A message of another type where the verdict belongs fails the
    /// exchange rather than being taken for one: here the capture-done
    /// message a capture left unread.
    #[test]
    fn another_messages_type_fails_the_settle_exchange() {
        let (handler, session) = demand_paged_session();
        let done = serde_json::to_vec(&CaptureOutcome::Success).unwrap();
        send_message(&handler, MSG_CAPTURE_DONE, &done, &[]).unwrap();

        let error = session.exchange_settle(A_MOMENT).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error.to_string().contains("unexpected message type 3"),
            "{error}"
        );
    }

    /// A verdict of a shape this VMM does not know, as another version of
    /// the exchange might send, fails the exchange.
    #[test]
    fn a_verdict_of_an_unknown_shape_fails_the_settle_exchange() {
        let (handler, session) = demand_paged_session();
        send_message(&handler, MSG_SETTLE_VERDICT, br#""Deferred""#, &[]).unwrap();

        let error = session.exchange_settle(A_MOMENT).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("Deferred"), "{error}");
    }

    /// A handler that holds the connection open and never answers fails the
    /// exchange once the deadline has passed, and not before: the settle
    /// reached it, and nothing came back.
    #[test]
    fn a_handler_that_never_answers_runs_into_the_deadline() {
        let (handler, session) = demand_paged_session();

        let asked = Instant::now();
        let error = session.exchange_settle(A_MOMENT).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(asked.elapsed() >= A_MOMENT, "{:?}", asked.elapsed());
        assert!(message_waits(&handler));
    }

    /// A verdict cut short is waited for no longer than the deadline
    /// either: the header arrives, and the body it announces never does.
    #[test]
    fn a_verdict_cut_short_runs_into_the_deadline() {
        let (handler, session) = demand_paged_session();
        let mut header = Vec::new();
        header.extend_from_slice(&MSG_SETTLE_VERDICT.to_le_bytes());
        header.extend_from_slice(&9u32.to_le_bytes());
        handler.send_with_fds(&[&header[..]], &[]).unwrap();

        let error = session.exchange_settle(A_MOMENT).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    }
}
