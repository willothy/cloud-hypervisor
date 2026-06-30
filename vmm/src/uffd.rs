// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal userfaultfd bindings for demand-paged snapshot restore.
//!
//! Prefers `/dev/userfaultfd` (Linux 6.1+) over the `userfaultfd(2)` syscall
//! to create a fault descriptor, falling back to the syscall when the device
//! is unavailable. Then uses `UFFDIO_API` / `UFFDIO_REGISTER` / `UFFDIO_COPY`
//! ioctls to handle page faults from a background thread.
//!
//! Unlike an mmap(MAP_PRIVATE) overlay approach, UFFD does not replace the
//! original memory mapping, so it remains compatible with VFIO device
//! passthrough and shared-memory-backed guest RAM.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Error, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;

use vm_migration::protocol::{MemoryRange, Request, Response, Status};

use crate::migration::transport::SocketStream;
use crate::userfaultfd;

#[repr(C)]
pub(crate) struct UffdioApi {
    pub api: u64,
    pub features: u64,
    pub ioctls: u64,
}

#[repr(C)]
pub(crate) struct UffdioRegister {
    pub range_start: u64,
    pub range_len: u64,
    pub mode: u64,
    pub ioctls: u64,
}

#[repr(C)]
pub(crate) struct UffdioCopy {
    pub dst: u64,
    pub src: u64,
    pub len: u64,
    pub mode: u64,
    pub copy: i64,
}

/// Flat representation of `struct uffd_msg` (32 bytes).
///
/// The kernel struct contains an 8-byte header followed by a 24-byte
/// union (`arg`). We only use the `arg.pagefault` variant, so the
/// union is flattened into its pagefault fields here. The trailing
/// 8 bytes (`arg.pagefault.feat` + padding) are unused.
#[repr(C)]
pub(crate) struct UffdMsg {
    pub event: u8,
    _reserved1: u8,
    _reserved2: u16,
    _reserved3: u32,
    pub pf_flags: u64,
    pub pf_address: u64,
    _pad: [u8; 8],
}

const _: () = assert!(size_of::<UffdMsg>() == 32);

/// Try to obtain a userfaultfd via /dev/userfaultfd (Linux 6.1+).
///
/// This bypasses the capability and sysctl checks that gate the syscall,
/// requiring only file permissions on the device node.
fn try_dev_userfaultfd() -> Result<OwnedFd, Error> {
    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/userfaultfd")?;
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: USERFAULTFD_IOC_NEW on a valid /dev/userfaultfd fd returns a new
    // userfaultfd file descriptor.
    let fd = unsafe {
        libc::ioctl(
            dev.as_raw_fd(),
            userfaultfd::USERFAULTFD_IOC_NEW as libc::Ioctl,
            flags,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the ioctl returned a valid fd above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a userfaultfd file descriptor and perform the API handshake.
///
/// Prefers `/dev/userfaultfd` (no capability/sysctl requirements, just file
/// permissions) and falls back to the `userfaultfd(2)` syscall.
pub(crate) fn create(required_features: u64) -> Result<OwnedFd, Error> {
    let fd = match try_dev_userfaultfd() {
        Ok(fd) => fd,
        Err(_) => {
            // SAFETY: `userfaultfd` syscall with O_CLOEXEC | O_NONBLOCK flags.
            let raw =
                unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if raw < 0 {
                return Err(Error::last_os_error());
            }
            // SAFETY: the syscall returned a valid fd above.
            unsafe { OwnedFd::from_raw_fd(raw as RawFd) }
        }
    };

    let mut api = UffdioApi {
        api: userfaultfd::UFFD_API,
        features: required_features,
        ioctls: 0,
    };
    // SAFETY: `api` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_API as libc::Ioctl,
            &mut api,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(fd)
}

/// Register a memory range for fault handling in the given mode
/// (`UFFDIO_REGISTER_MODE_MISSING` for demand paging,
/// `UFFDIO_REGISTER_MODE_WP` for write tracking, or their union).
pub(crate) fn register(fd: BorrowedFd<'_>, addr: u64, len: u64, mode: u64) -> Result<u64, Error> {
    let mut reg = UffdioRegister {
        range_start: addr,
        range_len: len,
        mode,
        ioctls: 0,
    };
    // SAFETY: `reg` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_REGISTER as libc::Ioctl,
            &mut reg,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(reg.ioctls)
}

/// Resolve a page fault by copying data into the faulted address.
pub(crate) fn copy(fd: BorrowedFd<'_>, dst: u64, src: *const u8, len: u64) -> Result<(), Error> {
    let mut cp = UffdioCopy {
        dst,
        src: src as u64,
        len,
        mode: 0,
        copy: 0,
    };
    // SAFETY: `cp` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_COPY as libc::Ioctl,
            &mut cp,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioWriteprotect {
    range: UffdioRange,
    mode: u64,
}

/// A guest memory range registered with userfaultfd, plus where its bytes
/// live for the data source.
pub(crate) struct UffdRange {
    pub host_addr: u64,
    pub length: u64,
    pub source_offset: u64,
    pub page_size: u64,
}

impl UffdRange {
    pub fn num_pages(&self) -> u64 {
        self.length.div_ceil(self.page_size)
    }

    pub fn page_addr(&self, page_idx: u64) -> u64 {
        self.host_addr + page_idx * self.page_size
    }

    pub fn page_source_offset(&self, page_idx: u64) -> u64 {
        self.source_offset + page_idx * self.page_size
    }

    pub fn page_index_of(&self, addr: u64) -> Option<u64> {
        let page_addr = addr & !(self.page_size - 1);
        (page_addr >= self.host_addr && page_addr < self.host_addr + self.length)
            .then(|| (page_addr - self.host_addr) / self.page_size)
    }
}

/// Result of a page fault being resolved.
pub(crate) enum FaultResolution {
    /// Page installed.
    Served,
    /// Indicates the page couldn't be installed and it's worth retrying.
    Retry,
}

/// Provider of guest-memory page contents for a UFFD handler.
pub(crate) trait UffdMemorySource: Send {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<FaultResolution, io::Error>;

    /// Resolve a contiguous run of up to `num_pages` pages starting at
    /// `start_page`, in as few operations as the source supports, returning
    /// the number of leading pages actually installed.
    ///
    /// The background prefault pass uses this to fill ahead of the guest in
    /// large strides instead of one page per round-trip. A returned count
    /// below `num_pages` (including zero) just means the caller resolves the
    /// rest later — those pages stay un-installed, so a guest access still
    /// faults them in normally. The default installs a single page via
    /// [`resolve`](UffdMemorySource::resolve); sources that can transfer a
    /// whole run at once override this.
    fn resolve_run(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        start_page: u64,
        num_pages: u64,
    ) -> Result<u64, io::Error> {
        let _ = num_pages;
        match self.resolve(uffd_fd, range, start_page)? {
            FaultResolution::Served => Ok(1),
            FaultResolution::Retry => Ok(0),
        }
    }
}

/// Source that reads pages from a local snapshot file.
pub(crate) struct FileUffdMemorySource {
    file: File,
    buf: Vec<u8>,
}

impl FileUffdMemorySource {
    pub fn new(file: File) -> Self {
        Self {
            file,
            buf: Vec::new(),
        }
    }
}

impl UffdMemorySource for FileUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<FaultResolution, io::Error> {
        let page_size = range.page_size as usize;
        let page_addr = range.page_addr(page_idx);
        let file_pos = range.page_source_offset(page_idx);

        if self.buf.len() < page_size {
            self.buf.resize(page_size, 0);
        }
        self.file
            .read_exact_at(&mut self.buf[..page_size], file_pos)?;

        match copy(uffd_fd, page_addr, self.buf.as_ptr(), range.page_size) {
            Ok(()) => Ok(FaultResolution::Served),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Installed concurrently. Wake any blocked threads.
                if let Err(e) = wake(uffd_fd, page_addr, range.page_size) {
                    log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                }
                Ok(FaultResolution::Served)
            }
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(FaultResolution::Retry),
            Err(e) => Err(e),
        }
    }
}

/// Memory source that provides pages content over a socket.
pub(crate) struct SocketUffdMemorySource {
    stream: SocketStream,
    shared_backing: bool,
    buf: Vec<u8>,
}

impl SocketUffdMemorySource {
    pub fn new(stream: SocketStream, shared_backing: bool) -> Self {
        Self {
            stream,
            shared_backing,
            buf: Vec::new(),
        }
    }

    /// Returns the length of the inline page payload the peer is about to send
    /// (0 when the page was written directly into shared memory).
    fn request_page(&mut self, gpa: u64, len: u64) -> Result<u64, io::Error> {
        Request::page_fault()
            .write_to(&mut self.stream)
            .map_err(io_other)?;
        MemoryRange { gpa, length: len }
            .write_to(&mut self.stream)
            .map_err(io_other)?;

        let resp = Response::read_from(&mut self.stream).map_err(io_other)?;
        match resp.status() {
            Status::Ok => Ok(resp.length()),
            s => Err(io::Error::other(format!(
                "peer returned {s:?} for PageFault at gpa={gpa:#x} len={len}",
            ))),
        }
    }
}

impl UffdMemorySource for SocketUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<FaultResolution, io::Error> {
        let page_size = range.page_size;
        let page_addr = range.page_addr(page_idx);
        let page_gpa = range.page_source_offset(page_idx);

        let resp_len = self.request_page(page_gpa, page_size)?;

        if self.shared_backing {
            if resp_len != 0 {
                return Err(io::Error::other(format!(
                    "shared-backing PageFault response carried {resp_len} unexpected bytes",
                )));
            }
            match wake(uffd_fd, page_addr, page_size) {
                Ok(()) => Ok(FaultResolution::Served),
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(FaultResolution::Retry),
                Err(e) => Err(e),
            }
        } else {
            if resp_len != page_size {
                return Err(io::Error::other(format!(
                    "inline PageFault response length {resp_len} != page size {page_size}",
                )));
            }
            let len = page_size as usize;
            if self.buf.len() < len {
                self.buf.resize(len, 0);
            }
            self.stream.read_exact(&mut self.buf[..len])?;
            match copy(uffd_fd, page_addr, self.buf.as_ptr(), page_size) {
                Ok(()) => Ok(FaultResolution::Served),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(FaultResolution::Served)
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(FaultResolution::Retry),
                Err(e) => Err(e),
            }
        }
    }

    fn resolve_run(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        start_page: u64,
        num_pages: u64,
    ) -> Result<u64, io::Error> {
        // Shared backing installs each page by waking its faulting thread, so
        // there is nothing to batch; the inline path transfers the whole run
        // in one request and installs it with a single UFFDIO_COPY.
        if self.shared_backing || num_pages <= 1 {
            return match self.resolve(uffd_fd, range, start_page)? {
                FaultResolution::Served => Ok(1),
                FaultResolution::Retry => Ok(0),
            };
        }

        let page_size = range.page_size;
        let run_pages = num_pages.min(range.num_pages() - start_page);
        let start_addr = range.page_addr(start_page);
        let start_gpa = range.page_source_offset(start_page);
        let bytes = run_pages * page_size;

        let resp_len = self.request_page(start_gpa, bytes)?;
        if resp_len != bytes {
            return Err(io::Error::other(format!(
                "inline PageFault response length {resp_len} != requested run {bytes}",
            )));
        }
        let len = bytes as usize;
        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }
        self.stream.read_exact(&mut self.buf[..len])?;

        match copy(uffd_fd, start_addr, self.buf.as_ptr(), bytes) {
            Ok(()) => Ok(run_pages),
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(0),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // A page in the run was already present (the caller builds runs
                // of un-installed pages, so this is rare). Install the run from
                // the buffer we already fetched, page by page, waking any page
                // that turns out present and stopping at the first the kernel
                // is still resolving.
                let mut installed = 0u64;
                while installed < run_pages {
                    let off = (installed * page_size) as usize;
                    let dst = start_addr + installed * page_size;
                    // SAFETY: `self.buf` holds `bytes` valid bytes; `off` is
                    // within it and `dst` is the matching guest page address.
                    let src = unsafe { self.buf.as_ptr().add(off) };
                    match copy(uffd_fd, dst, src, page_size) {
                        Ok(()) => {}
                        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                            if let Err(e) = wake(uffd_fd, dst, page_size) {
                                log::warn!("UFFDIO_WAKE failed at {dst:#x}: {e}");
                            }
                        }
                        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => break,
                        Err(e) => return Err(e),
                    }
                    installed += 1;
                }
                Ok(installed)
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for SocketUffdMemorySource {
    fn drop(&mut self) {
        // SAFETY: the fd is valid for the duration of this borrow.
        unsafe { libc::shutdown(self.stream.as_fd().as_raw_fd(), libc::SHUT_RDWR) };
    }
}

fn io_other<E: fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Arm or release write-protection on a registered range.
///
/// With `protect` set, each page in the range delivers a write-protect fault
/// (`UFFD_PAGEFAULT_FLAG_WP`) on the next write instead of completing it, so a
/// handler can copy the pre-write contents out first; clearing `protect`
/// releases the protection and, unless `dont_wake`, wakes any threads blocked
/// on a write fault in the range. The range must have been registered with
/// `UFFDIO_REGISTER_MODE_WP`.
pub(crate) fn write_protect(
    fd: BorrowedFd<'_>,
    addr: u64,
    len: u64,
    protect: bool,
    dont_wake: bool,
) -> Result<(), Error> {
    let mut mode = 0u64;
    if protect {
        mode |= userfaultfd::UFFDIO_WRITEPROTECT_MODE_WP;
    }
    if dont_wake {
        mode |= userfaultfd::UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
    }
    let mut wp = UffdioWriteprotect {
        range: UffdioRange { start: addr, len },
        mode,
    };
    // SAFETY: `wp` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_WRITEPROTECT as libc::Ioctl,
            &mut wp,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// One guest-memory range to capture, and where its pages land in the output.
pub(crate) struct CaptureRange {
    /// Start of the range in this process's address space.
    pub host_addr: u64,
    /// Length of the range in bytes.
    pub length: u64,
    /// Byte offset the range's first page maps to in the capture output.
    pub out_offset: u64,
    /// Page size the range is captured and protected at.
    pub page_size: u64,
}

impl CaptureRange {
    fn num_pages(&self) -> u64 {
        self.length.div_ceil(self.page_size)
    }
}

/// Read one pending write-protect fault without blocking, returning its
/// address, or `None` when the queue is drained (`EAGAIN`).
fn read_wp_fault(uffd_fd: BorrowedFd<'_>) -> Result<Option<u64>, Error> {
    let mut msg = std::mem::MaybeUninit::<UffdMsg>::uninit();
    // SAFETY: read up to one `UffdMsg`-sized record from the userfaultfd.
    let n = unsafe {
        libc::read(
            uffd_fd.as_raw_fd(),
            msg.as_mut_ptr().cast(),
            std::mem::size_of::<UffdMsg>(),
        )
    };
    if n < 0 {
        let e = Error::last_os_error();
        return if e.raw_os_error() == Some(libc::EAGAIN) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    if (n as usize) < std::mem::size_of::<UffdMsg>() {
        return Ok(None);
    }
    // SAFETY: a full `UffdMsg` was read above.
    let msg = unsafe { msg.assume_init() };
    if msg.event != userfaultfd::UFFD_EVENT_PAGEFAULT {
        return Ok(None);
    }
    Ok(Some(msg.pf_address))
}

/// Capture one page's pre-write contents and release its protection.
///
/// The page must be currently write-protected, so the guest cannot mutate it
/// between the read and the release: a concurrent write parks on the WP fault
/// and only proceeds once protection is cleared here.
fn capture_page<S>(
    uffd_fd: BorrowedFd<'_>,
    range: &CaptureRange,
    page_idx: u64,
    sink: &mut S,
) -> Result<(), io::Error>
where
    S: FnMut(u64, &[u8]) -> Result<(), io::Error>,
{
    let offset = page_idx * range.page_size;
    let page_addr = range.host_addr + offset;
    let len = (range.length - offset).min(range.page_size) as usize;
    // SAFETY: `[page_addr, page_addr + len)` lies within a mapped, present
    // guest-memory range that is write-protected for the duration of this read,
    // so its contents cannot change under us.
    let bytes = unsafe { std::slice::from_raw_parts(page_addr as *const u8, len) };
    sink(range.out_offset + offset, bytes)?;
    // Release protection (waking any writer parked on this page) now that the
    // pre-write contents are captured.
    write_protect(uffd_fd, page_addr, range.page_size, false, false)?;
    Ok(())
}

/// Capture a consistent, point-in-time copy of `ranges` while the guest keeps
/// running, using UFFD write-protect copy-on-write.
///
/// The ranges must already be registered `UFFDIO_REGISTER_MODE_WP` on
/// `uffd_fd` and have their protection armed. Each page's pre-write contents
/// are handed to `sink(out_offset, bytes)` exactly once and its protection is
/// then released. A background pass copies pages in order; a guest write to a
/// not-yet-copied page faults, that page is captured ahead of the pass, and
/// the write proceeds — so the captured image is the memory state at the
/// moment protection was armed, with no VM pause.
pub(crate) fn capture_write_protected<S>(
    uffd_fd: BorrowedFd<'_>,
    ranges: &[CaptureRange],
    mut sink: S,
) -> Result<(), io::Error>
where
    S: FnMut(u64, &[u8]) -> Result<(), io::Error>,
{
    // Flatten the ranges' pages into one index space, with prefix sums so a
    // faulting address maps back to its (range, page).
    let counts: Vec<u64> = ranges.iter().map(CaptureRange::num_pages).collect();
    let mut starts = Vec::with_capacity(ranges.len());
    let mut acc = 0u64;
    for c in &counts {
        starts.push(acc);
        acc += c;
    }
    let total = acc as usize;
    let mut captured = vec![false; total];

    let loc_of = |flat: usize| -> (usize, u64) {
        let ri = match starts.binary_search(&(flat as u64)) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (ri, flat as u64 - starts[ri])
    };
    let flat_of = |addr: u64| -> Option<usize> {
        ranges.iter().enumerate().find_map(|(ri, r)| {
            (addr >= r.host_addr && addr < r.host_addr + r.length)
                .then(|| (starts[ri] + (addr - r.host_addr) / r.page_size) as usize)
        })
    };

    let mut done = 0usize;
    let mut next = 0usize;
    while done < total {
        // Drain pending write faults so parked writers are served promptly.
        while let Some(addr) = read_wp_fault(uffd_fd)? {
            if let Some(flat) = flat_of(addr) {
                if !captured[flat] {
                    captured[flat] = true;
                    let (ri, pi) = loc_of(flat);
                    capture_page(uffd_fd, &ranges[ri], pi, &mut sink)?;
                    done += 1;
                }
            }
        }
        if done >= total {
            break;
        }
        // Advance the background pass to the next uncaptured page.
        while next < total && captured[next] {
            next += 1;
        }
        if next < total {
            captured[next] = true;
            let (ri, pi) = loc_of(next);
            capture_page(uffd_fd, &ranges[ri], pi, &mut sink)?;
            done += 1;
            next += 1;
        }
    }
    Ok(())
}

/// Wake threads waiting on a fault in the given range without copying data.
///
/// Needed after UFFDIO_COPY returns EEXIST: the page was already resolved
/// by a concurrent fault, but any additional threads blocked on that page
/// may not have been woken.
pub(crate) fn wake(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut range = UffdioRange { start: addr, len };
    // SAFETY: `range` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_WAKE as libc::Ioctl,
            &mut range,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::{UffdMsg, create, register, write_protect};
    use crate::userfaultfd::{
        UFFD_EVENT_PAGEFAULT, UFFD_FEATURE_PAGEFAULT_FLAG_WP, UFFD_PAGEFAULT_FLAG_WP,
        UFFDIO_REGISTER_MODE_WP,
    };

    const PAGE: usize = 4096;

    /// A present, write-protected page delivers a write-protect fault on the
    /// next write — carrying the faulting address and the WP flag — and the
    /// blocked write proceeds once protection is released. This exercises the
    /// whole WP path (register MODE_WP, arm, fault, release) against the kernel.
    #[test]
    fn write_protect_fault_roundtrip() {
        let len = 2 * PAGE;
        // SAFETY: anonymous private mapping; checked for MAP_FAILED below.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let base_addr = base as u64;
        // Populate both pages so they are present (WP tracks present pages).
        // SAFETY: `base` is a valid, writable `len`-byte mapping.
        unsafe { std::ptr::write_bytes(base.cast::<u8>(), 0xAB, len) };

        let uffd = create(UFFD_FEATURE_PAGEFAULT_FLAG_WP).expect("create uffd");
        register(uffd.as_fd(), base_addr, len as u64, UFFDIO_REGISTER_MODE_WP)
            .expect("register WP");
        write_protect(uffd.as_fd(), base_addr, len as u64, true, false).expect("arm WP");

        // Write to the second page from another thread; the store faults and
        // parks until protection is released.
        let page1 = base_addr + PAGE as u64;
        let writer = std::thread::spawn(move || {
            // SAFETY: `page1` is in the mapping; the store parks on the WP fault.
            unsafe { std::ptr::write_volatile(page1 as *mut u8, 0xCD) };
        });

        let fault_addr = poll_one_wp_fault(uffd.as_fd());
        assert_eq!(
            fault_addr & !(PAGE as u64 - 1),
            page1,
            "fault address is in the written page"
        );

        write_protect(uffd.as_fd(), page1, PAGE as u64, false, false).expect("release WP");
        writer.join().expect("writer joined");

        // SAFETY: `page1` is still mapped; read back the writer's byte.
        let written = unsafe { std::ptr::read_volatile(page1 as *const u8) };
        assert_eq!(written, 0xCD, "the writer's store landed after release");

        // SAFETY: unmap the region this test mapped.
        unsafe { libc::munmap(base, len) };
    }

    /// Read one `UFFD_EVENT_PAGEFAULT` carrying the WP flag, returning its
    /// address. The fd is non-blocking, so poll until a message arrives.
    fn poll_one_wp_fault(fd: std::os::fd::BorrowedFd<'_>) -> u64 {
        use std::os::fd::AsRawFd;
        loop {
            let mut pfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: a single valid pollfd with a 1s timeout.
            let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
            assert!(n >= 0, "poll failed: {}", std::io::Error::last_os_error());
            assert_ne!(n, 0, "timed out waiting for a write-protect fault");

            let mut msg = std::mem::MaybeUninit::<UffdMsg>::uninit();
            // SAFETY: read up to one `UffdMsg`-sized record from the uffd.
            let r = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    msg.as_mut_ptr().cast(),
                    std::mem::size_of::<UffdMsg>(),
                )
            };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EAGAIN) {
                    continue;
                }
                panic!("read uffd: {e}");
            }
            assert_eq!(
                r as usize,
                std::mem::size_of::<UffdMsg>(),
                "short uffd read"
            );
            // SAFETY: a full `UffdMsg` was read above.
            let msg = unsafe { msg.assume_init() };
            assert_eq!(msg.event, UFFD_EVENT_PAGEFAULT, "event is a pagefault");
            assert_ne!(
                msg.pf_flags & UFFD_PAGEFAULT_FLAG_WP,
                0,
                "fault carries the write-protect flag"
            );
            return msg.pf_address;
        }
    }
}
