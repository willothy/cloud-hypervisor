// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLockReadGuard};
use std::time::{Duration, Instant};
use std::{ffi, fs, io, slice};

use log::{error, info};
use vhost::vhost_kern::vhost_binding::VHOST_VRING_F_LOG;
use vhost::vhost_user::message::{
    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserHeaderFlag, VhostUserInflight,
    VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{
    Error as VhostUserError, Frontend, FrontendReqHandler, VhostUserFrontend,
    VhostUserFrontendReqHandler,
};
use vhost::{
    Error as VhostError, VhostBackend, VhostUserDirtyLogRegion, VhostUserMemoryRegionInfo,
    VringConfigData,
};
use virtio_queue::desc::RawDescriptor;
use virtio_queue::{Queue, QueueT};
use vm_memory::guest_memory::Error as MmapError;
use vm_memory::{Address, FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryRegion};
use vm_migration::protocol::MemoryRangeTable;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::timerfd::TimerFd;

use super::{BackendFaults, BackendMapping, Error, PostcopyConnection, Result, VhostUserState};
use crate::vhost_user::Inflight;
use crate::{
    GuestMemoryMmap, GuestRegionMmap, MmapRegion, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_IN_ORDER,
    VirtioInterrupt, VirtioInterruptType, get_host_address_range,
};

// Size of a dirty page for vhost-user.
const VHOST_LOG_PAGE: u64 = 0x1000;

#[derive(Debug, Clone)]
pub struct VhostUserConfig {
    pub socket: String,
    pub num_queues: usize,
    pub queue_size: u16,
}

#[derive(Clone)]
struct VringInfo {
    config_data: VringConfigData,
    used_guest_addr: u64,
}

pub struct VhostUserHandle {
    vu: Frontend,
    backend_features: u64,
    ready: bool,
    supports_migration: bool,
    supports_device_state: bool,
    shm_log: Option<Arc<MmapRegion>>,
    acked_features: u64,
    vrings_info: Option<Vec<VringInfo>>,
    queue_indexes: Vec<u16>,
    vring_bases: Option<Vec<u64>>,
    /// Set on a device created while guest RAM is demand-paged. Until it
    /// settles, the backend must negotiate `PAGEFAULT`, and every memory
    /// table it maps is registered with its postcopy userfaultfd and handed
    /// to the fault handler before it can touch guest RAM.
    faults: Option<BackendFaults>,
    /// Whether the backend negotiated `PAGEFAULT`.
    serves_faults: bool,
    /// The connection's place on the postcopy flow, from the moment the
    /// backend advised its userfaultfd: the id the fault handler knows it
    /// by, and its registration for the settle to end the flow on it.
    postcopy_connection: Option<PostcopyConnection>,
    /// The backend's userfaultfd, until the fault handler has adopted the
    /// connection's first memory table, which hands it over.
    unadopted_uffd: Option<File>,
}

impl VhostUserHandle {
    pub fn update_mem_table(&mut self, mem: &GuestMemoryMmap) -> Result<()> {
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        for region in mem.iter() {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => {
                    return Err(Error::VhostUserMemoryRegion(
                        MmapError::InvalidGuestAddress(region.start_addr()),
                    ));
                }
            };

            let vhost_user_net_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.as_ptr() as u64,
                mmap_offset,
                mmap_handle,
            };

            regions.push(vhost_user_net_reg);
        }

        if let Some(faults) = self.faults.clone() {
            let held = faults.paging.hold();
            if !*held {
                return self.set_mem_table_postcopy(&faults, &held, &regions);
            }
        }

        self.vu
            .set_mem_table(regions.as_slice())
            .map_err(Error::VhostUserSetMemTable)?;

        Ok(())
    }

    /// Give a backend serving faults its memory table the postcopy way: on
    /// the connection's first table, open its userfaultfd and have it listen;
    /// then send the table, hand the mappings the backend reports (and, the
    /// first time, its userfaultfd) to the fault handler, and only once the
    /// handler has adopted them acknowledge, which is what lets the backend
    /// touch guest RAM. A table the handler refuses fails the connection.
    /// The connection is registered for the settle to end the flow on it as
    /// soon as the backend has a userfaultfd, under `held`, the guard that
    /// found guest RAM still demand-paged.
    fn set_mem_table_postcopy(
        &mut self,
        faults: &BackendFaults,
        held: &RwLockReadGuard<'_, bool>,
        regions: &[VhostUserMemoryRegionInfo],
    ) -> Result<()> {
        if !self.serves_faults {
            return Err(Error::BackendServesNoFaults);
        }
        let connection = match &self.postcopy_connection {
            Some(connection) => connection.id(),
            None => {
                let uffd = self
                    .vu
                    .postcopy_advise()
                    .map_err(Error::VhostUserPostcopyAdvise)?;
                let connection = faults.paging.register(held, &self.vu);
                let id = connection.id();
                self.postcopy_connection = Some(connection);
                self.unadopted_uffd = Some(uffd);
                self.vu
                    .postcopy_listen()
                    .map_err(Error::VhostUserPostcopyListen)?;
                id
            }
        };
        let bases = self
            .vu
            .set_mem_table_postcopy(regions)
            .map_err(Error::VhostUserSetMemTable)?;
        let mappings = regions
            .iter()
            .zip(bases)
            .map(|(region, backend_addr)| {
                Ok(BackendMapping {
                    backend_addr,
                    vmm_addr: region.userspace_addr,
                    length: region.memory_size,
                    page_size: Self::backing_page_size(region.mmap_handle)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        faults
            .handler
            .adopt(
                &faults.device,
                connection,
                &mappings,
                self.unadopted_uffd.as_ref().map(|uffd| uffd.as_fd()),
            )
            .map_err(Error::AdoptBackendFaults)?;
        self.unadopted_uffd = None;
        self.vu
            .postcopy_ack_mem_table()
            .map_err(Error::VhostUserPostcopyAck)
    }

    /// The page size of the guest memory backed by the file `fd`: the huge
    /// page size on hugetlbfs, which reports it as the block size, else the
    /// base page size.
    fn backing_page_size(fd: RawFd) -> Result<u64> {
        /// `HUGETLBFS_MAGIC` from linux/magic.h.
        const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
        let mut statfs = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs fills the statfs it is given for a valid fd.
        if unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) } != 0 {
            return Err(Error::BackingPageSize(io::Error::last_os_error()));
        }
        // SAFETY: fstatfs succeeded, so it initialized the struct.
        let statfs = unsafe { statfs.assume_init() };
        // The field types differ between glibc and musl.
        #[allow(clippy::unnecessary_cast)]
        if statfs.f_type as u64 == HUGETLBFS_MAGIC {
            return Ok(statfs.f_bsize as u64);
        }
        // SAFETY: sysconf reads a system constant.
        match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
            size if size > 0 => Ok(size as u64),
            _ => Err(Error::BackingPageSize(io::Error::last_os_error())),
        }
    }

    /// Whether this connection's backend faults through the fault handler:
    /// on a device created while guest RAM was demand-paged, until it
    /// settles.
    fn demand_paged(&self) -> bool {
        self.faults
            .as_ref()
            .is_some_and(|faults| !faults.paging.settled())
    }

    pub fn add_memory_region(&mut self, region: &Arc<GuestRegionMmap>) -> Result<()> {
        let (mmap_handle, mmap_offset) = match region.file_offset() {
            Some(file_offset) => (file_offset.file().as_raw_fd(), file_offset.start()),
            None => return Err(Error::MissingRegionFd),
        };

        let region = VhostUserMemoryRegionInfo {
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: region.as_ptr() as u64,
            mmap_offset,
            mmap_handle,
        };

        self.vu
            .add_mem_region(&region)
            .map_err(Error::VhostUserAddMemReg)
    }

    pub fn negotiate_features_vhost_user(
        &mut self,
        avail_features: u64,
        avail_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<(u64, u64)> {
        let acked_features = avail_features & self.backend_features;
        // Read once, so a settle meanwhile cannot change what is required
        // of the backend from what it was offered.
        let demand_paged = self.demand_paged();
        let avail_protocol_features = if demand_paged {
            avail_protocol_features | VhostUserProtocolFeatures::PAGEFAULT
        } else {
            avail_protocol_features
        };

        let acked_protocol_features =
            if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
                let backend_protocol_features = self
                    .vu
                    .get_protocol_features()
                    .map_err(Error::VhostUserGetProtocolFeatures)?;

                let acked_protocol_features = avail_protocol_features & backend_protocol_features;

                self.vu
                    .set_protocol_features(acked_protocol_features)
                    .map_err(Error::VhostUserSetProtocolFeatures)?;

                acked_protocol_features
            } else {
                VhostUserProtocolFeatures::empty()
            };

        if avail_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK)
            && acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK)
        {
            self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
        }

        self.update_supported_protocol_features(acked_protocol_features.bits());
        if demand_paged && !self.serves_faults {
            return Err(Error::BackendServesNoFaults);
        }

        // PAGEFAULT belongs to this connection, not the device: a snapshot
        // that carried it would require it of every backend the device is
        // restored with, demand-paged or not.
        Ok((
            acked_features,
            (acked_protocol_features - VhostUserProtocolFeatures::PAGEFAULT).bits(),
        ))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn setup_vhost_user<S: VhostUserFrontendReqHandler>(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[(u16, Queue, EventFd)],
        virtio_interrupt: &dyn VirtioInterrupt,
        acked_features: u64,
        backend_req_handler: &Option<FrontendReqHandler<S>>,
        inflight: Option<&mut Inflight>,
        vring_bases: Option<&[u64]>,
    ) -> Result<()> {
        if let Some(bases) = &vring_bases
            && bases.len() != queues.len()
        {
            return Err(Error::VringBasesCountMismatch(bases.len(), queues.len()));
        }

        // May run more than once on the same handle (resume after snapshot)
        self.queue_indexes.clear();

        // ACCESS_PLATFORM can be offered to confidential guests, but vhost-user
        // gives it IOTLB semantics, which this frontend does not implement.
        let acked_features =
            acked_features & self.backend_features & !(1u64 << VIRTIO_F_ACCESS_PLATFORM);

        self.vu
            .set_features(acked_features)
            .map_err(Error::VhostUserSetFeatures)?;

        // Update internal value after it's been sent to the backend.
        self.acked_features = acked_features;

        // Let's first provide the memory table to the backend.
        self.update_mem_table(mem)?;

        // Send set_vring_num here, since it could tell backends, like SPDK,
        // how many virt queues to be handled, which backend required to know
        // at early stage.
        for (queue_index, queue, _) in queues.iter() {
            self.vu
                .set_vring_num(*queue_index as usize, queue.size())
                .map_err(Error::VhostUserSetVringNum)?;
        }

        // Setup for inflight I/O tracking shared memory.
        if let Some(inflight) = inflight {
            if inflight.fd.is_none() {
                let inflight_req_info = VhostUserInflight {
                    mmap_size: 0,
                    mmap_offset: 0,
                    num_queues: queues.len() as u16,
                    queue_size: queues[0].1.size(),
                };
                let (info, fd) = self
                    .vu
                    .get_inflight_fd(&inflight_req_info)
                    .map_err(Error::VhostUserGetInflight)?;
                inflight.info = info;
                inflight.fd = Some(fd);
            }
            // Unwrapping the inflight fd is safe here since we know it can't be None.
            self.vu
                .set_inflight_fd(&inflight.info, inflight.fd.as_ref().unwrap().as_raw_fd())
                .map_err(Error::VhostUserSetInflight)?;
        }

        let mut vrings_info = Vec::new();
        for (i, (queue_index, queue, queue_evt)) in queues.iter().enumerate() {
            let actual_size: usize = queue.size().into();

            let config_data = VringConfigData {
                queue_max_size: queue.max_size(),
                queue_size: queue.size(),
                flags: 0u32,
                desc_table_addr: get_host_address_range(
                    mem,
                    GuestAddress(queue.desc_table()),
                    actual_size * size_of::<RawDescriptor>(),
                )
                .ok_or(Error::DescriptorTableAddress)? as u64,
                // The used ring is {flags: u16; idx: u16; virtq_used_elem [{id: u16, len: u16}; actual_size]},
                // i.e. 4 + (4 + 4) * actual_size.
                used_ring_addr: get_host_address_range(
                    mem,
                    GuestAddress(queue.used_ring()),
                    4 + actual_size * 8,
                )
                .ok_or(Error::UsedAddress)? as u64,
                // The used ring is {flags: u16; idx: u16; elem [u16; actual_size]},
                // i.e. 4 + (2) * actual_size.
                avail_ring_addr: get_host_address_range(
                    mem,
                    GuestAddress(queue.avail_ring()),
                    4 + actual_size * 2,
                )
                .ok_or(Error::AvailAddress)? as u64,
                log_addr: None,
            };

            vrings_info.push(VringInfo {
                config_data,
                used_guest_addr: queue.used_ring(),
            });

            self.vu
                .set_vring_addr(*queue_index as usize, &config_data)
                .map_err(Error::VhostUserSetVringAddr)?;
            let base = if let Some(bases) = vring_bases {
                bases[i] as u16
            } else {
                queue
                    .avail_idx(mem, Ordering::Acquire)
                    .map_err(Error::GetAvailableIndex)?
                    .0
            };
            self.vu
                .set_vring_base(*queue_index as usize, base)
                .map_err(Error::VhostUserSetVringBase)?;

            if let Some(eventfd) =
                virtio_interrupt.notifier(VirtioInterruptType::Queue(*queue_index))
            {
                self.vu
                    .set_vring_call(*queue_index as usize, &eventfd)
                    .map_err(Error::VhostUserSetVringCall)?;
            }

            self.vu
                .set_vring_kick(*queue_index as usize, queue_evt)
                .map_err(Error::VhostUserSetVringKick)?;

            self.queue_indexes.push(*queue_index);
        }

        self.enable_vhost_user_vrings(self.queue_indexes.clone(), true)?;

        if let Some(backend_req_handler) = backend_req_handler {
            self.vu
                .set_backend_request_fd(&backend_req_handler.get_tx_raw_fd())
                .map_err(Error::VhostUserSetBackendRequestFd)?;
        }

        self.vrings_info = Some(vrings_info);
        self.ready = true;

        Ok(())
    }

    fn enable_vhost_user_vrings(&mut self, queue_indexes: Vec<u16>, enable: bool) -> Result<()> {
        for queue_index in queue_indexes {
            self.vu
                .set_vring_enable(queue_index as usize, enable)
                .map_err(Error::VhostUserSetVringEnable)?;
        }

        Ok(())
    }

    pub fn reset_vhost_user(&mut self) -> Result<()> {
        for queue_index in self.queue_indexes.drain(..) {
            self.vu
                .set_vring_enable(queue_index as usize, false)
                .map_err(Error::VhostUserSetVringEnable)?;

            let _ = self
                .vu
                .get_vring_base(queue_index as usize)
                .map_err(Error::VhostUserGetVringBase)?;
        }

        Ok(())
    }

    pub fn set_protocol_features_vhost_user(
        &mut self,
        acked_features: u64,
        mut acked_protocol_features: u64,
    ) -> Result<()> {
        // PAGEFAULT is negotiated per connection, from whether guest RAM is
        // demand-paged now, never from what was saved: a device hot-plugged
        // while guest RAM was demand-paged by an earlier build saved it.
        acked_protocol_features &= !VhostUserProtocolFeatures::PAGEFAULT.bits();
        let demand_paged = self.demand_paged();
        if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            let backend_protocol_features = self
                .vu
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
            let unsupported = acked_protocol_features & !backend_protocol_features.bits();
            if unsupported != 0 {
                return Err(Error::UnsupportedProtocolFeatures(unsupported));
            }
            // A demand-paged restore needs PAGEFAULT of every backend that
            // offers it, and refuses the rest below.
            if demand_paged {
                acked_protocol_features |=
                    (backend_protocol_features & VhostUserProtocolFeatures::PAGEFAULT).bits();
                if acked_protocol_features & VhostUserProtocolFeatures::PAGEFAULT.bits() == 0 {
                    return Err(Error::BackendServesNoFaults);
                }
            }

            let acked = VhostUserProtocolFeatures::from_bits_truncate(acked_protocol_features);
            self.vu
                .set_protocol_features(acked)
                .map_err(Error::VhostUserSetProtocolFeatures)?;

            if acked.contains(VhostUserProtocolFeatures::REPLY_ACK) {
                self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
            }
        } else if acked_protocol_features != 0 {
            return Err(Error::InconsistentProtocolFeatures(acked_protocol_features));
        }

        self.update_supported_protocol_features(acked_protocol_features);
        if demand_paged && !self.serves_faults {
            return Err(Error::BackendServesNoFaults);
        }

        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    pub fn reinitialize_vhost_user<S: VhostUserFrontendReqHandler>(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[(u16, Queue, EventFd)],
        virtio_interrupt: &dyn VirtioInterrupt,
        acked_features: u64,
        acked_protocol_features: u64,
        backend_req_handler: &Option<FrontendReqHandler<S>>,
        inflight: Option<&mut Inflight>,
    ) -> Result<()> {
        self.set_protocol_features_vhost_user(acked_features, acked_protocol_features)?;

        // With in-order processing, used_idx is a contiguous completion boundary.
        // Replay descriptors after it when inflight tracking is not available to
        // recover them more precisely.
        let vring_bases = if inflight.is_none() && acked_features & (1u64 << VIRTIO_F_IN_ORDER) != 0
        {
            let mut vring_bases = Vec::with_capacity(queues.len());
            for (_, queue, _) in queues {
                let used_idx = queue
                    .used_idx(mem, Ordering::Acquire)
                    .map_err(Error::GetUsedIndex)?
                    .0;
                vring_bases.push(u64::from(used_idx));
            }
            Some(vring_bases)
        } else {
            None
        };

        self.setup_vhost_user(
            mem,
            queues,
            virtio_interrupt,
            acked_features,
            backend_req_handler,
            inflight,
            vring_bases.as_deref(),
        )?;

        for (_, _, queue_evt) in queues {
            queue_evt.write(1).map_err(Error::VhostUserKickVring)?;
        }

        Ok(())
    }

    pub fn connect_vhost_user(
        server: bool,
        socket_path: &str,
        num_queues: u64,
        unlink_socket: bool,
        kill_evt: &EventFd,
        faults: Option<&BackendFaults>,
        mut initialize: impl FnMut(&mut Self) -> Result<()>,
    ) -> Result<Self> {
        if server {
            if unlink_socket {
                fs::remove_file(socket_path).map_err(Error::RemoveSocketPath)?;
            }

            info!("Binding vhost-user listener...");
            let listener = UnixListener::bind(socket_path).map_err(Error::BindSocket)?;
            info!("Waiting for incoming vhost-user connection...");
            let (stream, _) = listener.accept().map_err(Error::AcceptConnection)?;

            let mut vhost_user = Self {
                vu: Frontend::from_stream(stream, num_queues),
                backend_features: 0,
                ready: false,
                supports_migration: false,
                supports_device_state: false,
                shm_log: None,
                acked_features: 0,
                vrings_info: None,
                queue_indexes: Vec::new(),
                vring_bases: None,
                faults: faults.cloned(),
                serves_faults: false,
                postcopy_connection: None,
                unadopted_uffd: None,
            };
            vhost_user
                .vu
                .set_owner()
                .map_err(Error::VhostUserSetOwner)?;
            vhost_user.backend_features = vhost_user
                .vu
                .get_features()
                .map_err(Error::VhostUserGetFeatures)?;
            initialize(&mut vhost_user)?;
            Ok(vhost_user)
        } else {
            const RETRY_INTERVAL: Duration = Duration::from_millis(100);
            const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

            #[repr(u64)]
            enum ConnectEvent {
                Timer = 0,
                Kill = 1,
            }

            let mut retry_timer = TimerFd::new().map_err(|e| Error::TimerFdCreate(e.into()))?;
            retry_timer
                .reset(RETRY_INTERVAL, Some(RETRY_INTERVAL))
                .map_err(|e| Error::TimerFdArm(e.into()))?;

            let epoll = Epoll::new().map_err(Error::EpollCreate)?;
            epoll
                .ctl(
                    ControlOperation::Add,
                    retry_timer.as_raw_fd(),
                    EpollEvent::new(EventSet::IN, ConnectEvent::Timer as u64),
                )
                .map_err(Error::EpollCtl)?;

            epoll
                .ctl(
                    ControlOperation::Add,
                    kill_evt.as_raw_fd(),
                    EpollEvent::new(EventSet::IN, ConnectEvent::Kill as u64),
                )
                .map_err(Error::EpollCtl)?;

            let start = Instant::now();
            let mut events = [EpollEvent::default(); 1];

            loop {
                let connection = Frontend::connect(socket_path, num_queues)
                    .map(|vu| Self {
                        vu,
                        backend_features: 0,
                        ready: false,
                        supports_migration: false,
                        supports_device_state: false,
                        shm_log: None,
                        acked_features: 0,
                        vrings_info: None,
                        queue_indexes: Vec::new(),
                        vring_bases: None,
                        faults: faults.cloned(),
                        serves_faults: false,
                        postcopy_connection: None,
                        unadopted_uffd: None,
                    })
                    .map_err(Error::VhostUserConnect);

                let (err, connect_failed) = match connection {
                    Ok(mut vhost_user) => match vhost_user
                        .vu
                        .set_owner()
                        .map_err(Error::VhostUserSetOwner)
                        .and_then(|()| {
                            vhost_user.backend_features = vhost_user
                                .vu
                                .get_features()
                                .map_err(Error::VhostUserGetFeatures)?;
                            initialize(&mut vhost_user)
                        }) {
                        Ok(()) => return Ok(vhost_user),
                        Err(e) if e.is_transport_lost() => (e, false),
                        Err(e) => return Err(e),
                    },
                    Err(Error::VhostUserConnect(err)) => {
                        let retryable = match &err {
                            VhostError::VhostUserProtocol(VhostUserError::SocketConnect(
                                io_err,
                            )) => {
                                matches!(
                                    io_err.kind(),
                                    io::ErrorKind::NotFound
                                        | io::ErrorKind::Interrupted
                                        | io::ErrorKind::ConnectionRefused
                                )
                            }
                            _ => false,
                        };

                        if !retryable {
                            error!(
                                "Failed connecting to vhost-user backend for socket {socket_path}: {err:?}"
                            );
                            return Err(Error::VhostUserConnect(err));
                        }

                        (Error::VhostUserConnect(err), true)
                    }
                    Err(e) => return Err(e),
                };

                if start.elapsed() >= CONNECT_TIMEOUT {
                    if connect_failed {
                        error!(
                            "Timed out waiting for vhost-user connection on socket {socket_path}"
                        );
                        return Err(Error::VhostUserConnectTimeout);
                    }
                    return Err(err);
                }

                loop {
                    match epoll.wait(-1, &mut events) {
                        Ok(_) => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(Error::EpollWait(e)),
                    }
                }

                match events[0].data() {
                    x if x == ConnectEvent::Kill as u64 => {
                        info!(
                            "Aborting vhost-user connect for socket {socket_path}: kill event received"
                        );
                        return Err(Error::ConnectKilled);
                    }
                    x if x == ConnectEvent::Timer as u64 => {
                        // Drain the timerfd to clear the event.
                        retry_timer
                            .wait()
                            .map_err(|e| Error::TimerFdWait(e.into()))?;
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    /// The virtio features the backend offered in reply to `GET_FEATURES`
    /// when this connection was set up.
    pub fn backend_features(&self) -> u64 {
        self.backend_features
    }

    pub fn socket_handle(&mut self) -> &mut Frontend {
        &mut self.vu
    }

    pub fn pause_vhost_user(&mut self) -> Result<()> {
        if self.ready {
            self.enable_vhost_user_vrings(self.queue_indexes.clone(), false)?;
        }

        Ok(())
    }

    fn resume_vhost_user(&mut self) -> Result<()> {
        if self.ready {
            self.enable_vhost_user_vrings(self.queue_indexes.clone(), true)?;
        }

        Ok(())
    }

    fn update_supported_protocol_features(&mut self, acked_protocol_features: u64) {
        self.supports_migration = self.backend_features & VhostUserVirtioFeatures::LOG_ALL.bits()
            != 0
            && acked_protocol_features & VhostUserProtocolFeatures::LOG_SHMFD.bits() != 0;
        self.supports_device_state =
            acked_protocol_features & VhostUserProtocolFeatures::DEVICE_STATE.bits() != 0;
        self.serves_faults =
            acked_protocol_features & VhostUserProtocolFeatures::PAGEFAULT.bits() != 0;
    }

    pub fn supports_device_state(&self) -> bool {
        self.supports_device_state
    }

    /// Save backend device state via the SET_DEVICE_STATE_FD protocol.
    /// Returns the opaque state blob and per-queue vring base indices.
    pub fn save_backend_state(&mut self) -> Result<(Vec<u8>, Vec<u64>)> {
        // GET_VRING_BASE for each queue to stop the backend and capture indices
        let mut vring_bases = Vec::new();
        for queue_index in &self.queue_indexes {
            let base = self
                .vu
                .get_vring_base(*queue_index as usize)
                .map_err(Error::VhostUserGetVringBase)?;
            vring_bases.push(base as u64);
        }

        // The backend considers the vrings stopped after GET_VRING_BASE.
        self.ready = false;

        let (local, remote) = UnixStream::pair().map_err(Error::SaveRestoreBackendState)?;

        let mut read_file: File = match self
            .vu
            .set_device_state_fd(
                VhostTransferStateDirection::SAVE,
                VhostTransferStatePhase::STOPPED,
                remote.into(),
            )
            .map_err(Error::VhostUserSetDeviceStateFd)?
        {
            Some(file) => file,
            None => OwnedFd::from(local).into(),
        };

        // Read all state from the socket
        let mut state = Vec::new();
        read_file
            .read_to_end(&mut state)
            .map_err(Error::SaveRestoreBackendState)?;

        // Verify the transfer succeeded
        self.vu
            .check_device_state()
            .map_err(Error::VhostUserCheckDeviceState)?;

        // Store the bases in case we need to resume after snapshot
        self.vring_bases = Some(vring_bases.clone());

        Ok((state, vring_bases))
    }

    /// Resume the vhost-user backend from the device thread.
    /// Initialize the vrings from the bases captured earlier, or simply
    /// enable them if they haven't been stopped.
    pub fn resume<S: VhostUserFrontendReqHandler>(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[(u16, Queue, EventFd)],
        virtio_interrupt: &dyn VirtioInterrupt,
        acked_features: u64,
        backend_req_handler: &Option<FrontendReqHandler<S>>,
        inflight: Option<&mut Inflight>,
    ) -> Result<()> {
        let Some(vring_bases) = self.vring_bases.take() else {
            return self.resume_vhost_user();
        };

        self.setup_vhost_user(
            mem,
            queues,
            virtio_interrupt,
            acked_features,
            backend_req_handler,
            inflight,
            Some(&vring_bases),
        )
    }

    pub fn restore_state<C>(&mut self, state: &VhostUserState<C>) -> Result<()> {
        state.validate()?;
        if let Some(backend_state) = &state.backend_state {
            self.restore_backend_state(backend_state)?;
        }
        Ok(())
    }

    /// Restore backend device state via the SET_DEVICE_STATE_FD protocol.
    /// Sends the saved opaque state blob to the backend via a socket.
    pub fn restore_backend_state(&mut self, state: &[u8]) -> Result<()> {
        let (local, remote) = UnixStream::pair().map_err(Error::SaveRestoreBackendState)?;

        // Explicit scope to close the write end and signal EOF to the backend
        {
            let mut write_file: File = match self
                .vu
                .set_device_state_fd(
                    VhostTransferStateDirection::LOAD,
                    VhostTransferStatePhase::STOPPED,
                    remote.into(),
                )
                .map_err(Error::VhostUserSetDeviceStateFd)?
            {
                Some(file) => file,
                None => OwnedFd::from(local).into(),
            };

            // Write the saved state to the socket
            write_file
                .write_all(state)
                .map_err(Error::SaveRestoreBackendState)?;
        }

        // Verify the transfer succeeded
        self.vu
            .check_device_state()
            .map_err(Error::VhostUserCheckDeviceState)?;

        Ok(())
    }

    fn update_log_base(&mut self, last_ram_addr: u64) -> Result<Option<Arc<MmapRegion>>> {
        // Create the memfd
        let fd = memfd_create(
            &ffi::CString::new("vhost_user_dirty_log").unwrap(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
        .map_err(Error::MemfdCreate)?;

        // SAFETY: we checked the file descriptor is valid
        let file = unsafe { File::from_raw_fd(fd) };
        // The size of the memory mapping corresponds to the size of a bitmap
        // covering all guest pages for addresses from 0 to the last physical
        // address in guest RAM.
        // A page is always 4kiB from a vhost-user perspective, and each bit is
        // a page. That's how we can compute mmap_size from the last address.
        let mmap_size = (last_ram_addr / (VHOST_LOG_PAGE * 8)) + 1;
        let mmap_handle = file.as_raw_fd();

        // Set shm_log region size
        file.set_len(mmap_size).map_err(Error::SetFileSize)?;

        // Set the seals
        // SAFETY: FFI call with valid arguments
        let res = unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        };
        if res < 0 {
            return Err(Error::SetSeals(io::Error::last_os_error()));
        }

        // Mmap shm_log region
        let region = MmapRegion::build(
            Some(FileOffset::new(file, 0)),
            mmap_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
        )
        .map_err(Error::NewMmapRegion)?;

        // Make sure we hold onto the region to prevent the mapping from being
        // released.
        let old_region = self.shm_log.replace(Arc::new(region));

        // Send the shm_log fd over to the backend
        let log = VhostUserDirtyLogRegion {
            mmap_size,
            mmap_offset: 0,
            mmap_handle,
        };
        self.vu
            .set_log_base(0, Some(log))
            .map_err(Error::VhostUserSetLogBase)?;

        Ok(old_region)
    }

    fn set_vring_logging(&mut self, enable: bool) -> Result<()> {
        if let Some(vrings_info) = &self.vrings_info {
            for (i, vring_info) in vrings_info.iter().enumerate() {
                let mut config_data = vring_info.config_data;
                config_data.flags = if enable { 1 << VHOST_VRING_F_LOG } else { 0 };
                config_data.log_addr = if enable {
                    Some(vring_info.used_guest_addr)
                } else {
                    None
                };

                self.vu
                    .set_vring_addr(i, &config_data)
                    .map_err(Error::VhostUserSetVringAddr)?;
            }
        }

        Ok(())
    }

    pub fn start_dirty_log(&mut self, last_ram_addr: u64) -> Result<()> {
        if !self.supports_migration {
            return Err(Error::MigrationNotSupported);
        }

        // Set the shm log region
        self.update_log_base(last_ram_addr)?;

        // Enable VHOST_F_LOG_ALL feature
        let features = self.acked_features | VhostUserVirtioFeatures::LOG_ALL.bits();
        self.vu
            .set_features(features)
            .map_err(Error::VhostUserSetFeatures)?;

        // Enable dirty page logging of used ring for all queues
        self.set_vring_logging(true)
    }

    pub fn stop_dirty_log(&mut self) -> Result<()> {
        if !self.supports_migration {
            return Err(Error::MigrationNotSupported);
        }

        // Disable dirty page logging of used ring for all queues
        self.set_vring_logging(false)?;

        // Disable VHOST_F_LOG_ALL feature
        self.vu
            .set_features(self.acked_features)
            .map_err(Error::VhostUserSetFeatures)?;

        // This is important here since the log region goes out of scope,
        // invoking the Drop trait, hence unmapping the memory.
        self.shm_log = None;

        Ok(())
    }

    pub fn dirty_log(&mut self, last_ram_addr: u64) -> Result<MemoryRangeTable> {
        if !self.supports_migration {
            return Err(Error::MigrationNotSupported);
        }

        // The log region is updated by creating a new region that is sent to
        // the backend. This ensures the backend stops logging to the previous
        // region. The previous region is returned and processed to create the
        // bitmap representing the dirty pages.
        if let Some(region) = self.update_log_base(last_ram_addr)? {
            // Be careful with the size, as it was based on u8, meaning we must
            // divide it by 8.
            let len = region.size() / 8;
            // SAFETY: region is of size len
            let bitmap: &[u64] = unsafe {
                // Cast the pointer to u64
                let ptr = region.as_ptr().cast();
                slice::from_raw_parts(ptr, len)
            };
            Ok(MemoryRangeTable::from_dirty_bitmap(
                bitmap.iter().copied(),
                0,
                4096,
            ))
        } else {
            Err(Error::MissingShmLogRegion)
        }
    }
}

fn memfd_create(name: &ffi::CStr, flags: u32) -> io::Result<RawFd> {
    // SAFETY: FFI call with valid arguments
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::BorrowedFd;
    use std::thread;

    use vhost::vhost_user::message::{FrontendReq, VhostUserHeaderFlag};
    use vmm_sys_util::sock_ctrl_msg::ScmSocket;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::GuestMemoryMmap;
    use crate::vhost_user::{BackendFaultHandler, DemandPaging, SettleError};

    /// A fault handler for tests whose backends never get a postcopy table.
    struct Unused;

    impl BackendFaultHandler for Unused {
        fn adopt(
            &self,
            _: &str,
            _: u64,
            _: &[BackendMapping],
            _: Option<BorrowedFd<'_>>,
        ) -> io::Result<()> {
            Err(io::Error::other("no postcopy table is sent"))
        }
    }

    /// Read one request from the frontend, check it is `expected`, and
    /// return its payload.
    fn read_request(stream: &mut UnixStream, expected: FrontendReq) -> Vec<u8> {
        let mut header = [0u8; 12];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(
            u32::from_ne_bytes(header[0..4].try_into().unwrap()),
            u32::from(expected)
        );
        let size = u32::from_ne_bytes(header[8..12].try_into().unwrap()) as usize;
        let mut payload = vec![0; size];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    /// Reply to `request` with the 64-bit `value`: a feature set, or an
    /// acknowledgement, zero for success.
    fn reply(stream: &mut UnixStream, request: FrontendReq, value: u64) {
        for field in [u32::from(request), VhostUserHeaderFlag::REPLY.bits() | 1, 8] {
            stream.write_all(&field.to_ne_bytes()).unwrap();
        }
        stream.write_all(&value.to_ne_bytes()).unwrap();
    }

    /// A backend's connection made while guest RAM is `paging`'s to settle:
    /// the handshake that negotiates PAGEFAULT and REPLY_ACK, played by
    /// `backend` on its end, which then goes on as the test needs. With
    /// `registered` the connection is registered on the postcopy flow, as
    /// its first postcopy table leaves it. Returns the frontend's handle,
    /// the backend's thread, and the directory of its socket.
    fn postcopy_connection(
        paging: &Arc<DemandPaging>,
        registered: bool,
        backend: impl FnOnce(UnixStream) + Send + 'static,
    ) -> (VhostUserHandle, thread::JoinHandle<()>, TempDir) {
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let offered = (VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::PAGEFAULT)
            .bits();
        let dir = TempDir::new_with_prefix("/tmp/vhost-user-postcopy-end-").unwrap();
        let socket = dir.as_path().join("backend.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let backend = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
            reply(&mut stream, FrontendReq::GET_FEATURES, protocol_features);
            assert!(read_request(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES).is_empty());
            reply(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES, offered);
            assert_eq!(
                read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                offered.to_ne_bytes()
            );
            backend(stream);
        });

        let faults = BackendFaults {
            device: "_disk0".to_owned(),
            handler: Arc::new(Unused),
            paging: Arc::clone(paging),
        };
        let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut vu = VhostUserHandle::connect_vhost_user(
            false,
            socket.to_str().unwrap(),
            1,
            false,
            &kill_evt,
            Some(&faults),
            |vu| {
                vu.negotiate_features_vhost_user(
                    protocol_features,
                    VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::REPLY_ACK,
                )
                .map(|_| ())
            },
        )
        .unwrap();
        if registered {
            vu.postcopy_connection = Some(paging.register(&paging.hold(), &vu.vu));
        }
        (vu, backend, dir)
    }

    /// A guest memory of one 4 KiB page, backed by a file in `dir`.
    fn guest_memory(dir: &TempDir) -> GuestMemoryMmap {
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.as_path().join("memory"))
            .unwrap();
        file.set_len(0x1000).unwrap();
        GuestMemoryMmap::from_ranges_with_files(&[(
            GuestAddress(0),
            0x1000,
            Some(FileOffset::new(file, 0)),
        )])
        .unwrap()
    }

    /// Whether any connection is still registered on `paging`'s postcopy
    /// flow.
    fn any_on_the_flow(paging: &DemandPaging) -> bool {
        !paging.connections.lock().unwrap().is_empty()
    }

    /// A settled verdict leaves no connection on the postcopy flow: the
    /// settle ends it on every connection registered, one whose first
    /// table failed after the backend advised its userfaultfd included,
    /// before it records guest RAM as settled. A verdict of not yet ends
    /// nothing, and a settle after the first sends nothing more.
    #[test]
    fn a_settled_verdict_leaves_no_connection_in_postcopy() {
        let paging = Arc::new(DemandPaging::default());
        let ended = |mut stream: UnixStream| {
            assert!(read_request(&mut stream, FrontendReq::POSTCOPY_END).is_empty());
            reply(&mut stream, FrontendReq::POSTCOPY_END, 0);
            assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        };
        let (advised, advised_backend, dir) =
            postcopy_connection(&paging, false, move |mut stream| {
                assert!(read_request(&mut stream, FrontendReq::POSTCOPY_ADVISE).is_empty());
                let (uffd, _) = io::pipe().unwrap();
                let header: Vec<u8> = [
                    u32::from(FrontendReq::POSTCOPY_ADVISE),
                    VhostUserHeaderFlag::REPLY.bits() | 1,
                    0,
                ]
                .iter()
                .flat_map(|field| field.to_ne_bytes())
                .collect();
                stream.send_with_fd(&header[..], uffd.as_raw_fd()).unwrap();
                assert!(read_request(&mut stream, FrontendReq::POSTCOPY_LISTEN).is_empty());
                reply(&mut stream, FrontendReq::POSTCOPY_LISTEN, 1);
                ended(stream);
            });
        let mut advised = advised;
        let (registered, registered_backend, _registered_dir) =
            postcopy_connection(&paging, true, ended);

        assert!(matches!(
            advised.update_mem_table(&guest_memory(&dir)),
            Err(Error::VhostUserPostcopyListen(_))
        ));
        assert!(!paging.settle(|| Ok::<_, ()>(false)).unwrap());
        assert!(any_on_the_flow(&paging));

        assert!(paging.settle(|| Ok::<_, ()>(true)).unwrap());
        assert!(paging.settled());
        assert!(!any_on_the_flow(&paging));
        assert!(
            paging
                .settle(|| -> Result<bool> { panic!("a second exchange") })
                .unwrap()
        );

        drop(advised);
        drop(registered);
        advised_backend.join().unwrap();
        registered_backend.join().unwrap();
    }

    /// A backend that refuses to end the postcopy flow may still be
    /// registered for missing faults, so it fails the settle, naming its
    /// connection, and guest RAM stays recorded as demand-paged.
    #[test]
    fn a_refused_end_fails_the_settle() {
        let paging = Arc::new(DemandPaging::default());
        let (vu, backend, _dir) = postcopy_connection(&paging, true, |mut stream| {
            assert!(read_request(&mut stream, FrontendReq::POSTCOPY_END).is_empty());
            reply(&mut stream, FrontendReq::POSTCOPY_END, 1);
            assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        });
        let registered = vu.postcopy_connection.as_ref().unwrap().id();

        match paging.settle(|| Ok::<_, ()>(true)) {
            Err(SettleError::EndRefused { connection, .. }) => assert_eq!(connection, registered),
            other => panic!("unexpected settle result: {other:?}"),
        }
        assert!(!paging.settled());

        drop(vu);
        backend.join().unwrap();
    }

    /// A connection lost before the settle ends it has nothing left to end,
    /// and the settle goes through.
    #[test]
    fn a_lost_connection_does_not_fail_the_settle() {
        let paging = Arc::new(DemandPaging::default());
        let (vu, backend, _dir) = postcopy_connection(&paging, true, drop);
        backend.join().unwrap();

        assert!(paging.settle(|| Ok::<_, ()>(true)).unwrap());
        assert!(!any_on_the_flow(&paging));
        drop(vu);
    }

    /// A connection dropped before the settle leaves the register, and the
    /// settle sends it nothing.
    #[test]
    fn a_dropped_connection_leaves_the_register() {
        let paging = Arc::new(DemandPaging::default());
        let (vu, backend, _dir) = postcopy_connection(&paging, true, |mut stream| {
            assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        });
        assert!(any_on_the_flow(&paging));

        drop(vu);
        assert!(!any_on_the_flow(&paging));
        assert!(paging.settle(|| Ok::<_, ()>(true)).unwrap());
        backend.join().unwrap();
    }

    /// A memory table sent after the settle, on a connection the settle
    /// ended, is a plain one.
    #[test]
    fn a_table_after_the_settle_is_a_plain_one() {
        let paging = Arc::new(DemandPaging::default());
        let (mut vu, backend, dir) = postcopy_connection(&paging, true, |mut stream| {
            assert!(read_request(&mut stream, FrontendReq::POSTCOPY_END).is_empty());
            reply(&mut stream, FrontendReq::POSTCOPY_END, 0);
            assert_eq!(
                read_request(&mut stream, FrontendReq::SET_MEM_TABLE).len(),
                40
            );
            reply(&mut stream, FrontendReq::SET_MEM_TABLE, 0);
            assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        });

        assert!(paging.settle(|| Ok::<_, ()>(true)).unwrap());
        vu.update_mem_table(&guest_memory(&dir)).unwrap();

        drop(vu);
        backend.join().unwrap();
    }
}
