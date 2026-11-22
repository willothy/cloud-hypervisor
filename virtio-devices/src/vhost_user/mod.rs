// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{File, remove_file};
use std::io::ErrorKind;
use std::mem;
use std::ops::Deref;
use std::os::fd::BorrowedFd;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock, RwLockReadGuard};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vhost::Error as VhostError;
use vhost::vhost_user::message::{
    VhostUserInflight, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{
    Error as VhostUserError, Frontend, FrontendReqHandler, VhostUserFrontend,
    VhostUserFrontendReqHandler,
};
use virtio_queue::{Error as QueueError, Queue};
use vm_memory::guest_memory::Error as MmapError;
use vm_memory::mmap::MmapRegionError;
use vm_memory::{Address, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryBackend};
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{MigratableError, Pausable, Snapshot};
use vmm_sys_util::eventfd::EventFd;
use vu_common_ctrl::VhostUserHandle;

use crate::seccomp_filters::Thread;
use crate::{
    ActivateError, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    GuestMemoryMmap, GuestRegionMmap, VIRTIO_F_IN_ORDER, VIRTIO_F_NOTIFICATION_DATA,
    VIRTIO_F_ORDER_PLATFORM, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC,
    VIRTIO_F_VERSION_1, VirtioCommon, VirtioInterrupt,
};

pub mod blk;
pub mod fs;
pub mod generic_vhost_user;
pub mod net;
pub mod vu_common_ctrl;

pub use self::blk::Blk;
pub use self::fs::*;
pub use self::generic_vhost_user::GenericVhostUser;
pub use self::net::Net;
pub use self::vu_common_ctrl::VhostUserConfig;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed accepting connection")]
    AcceptConnection(#[source] io::Error),
    #[error("Invalid available address")]
    AvailAddress,
    #[error("Queue number  is not correct")]
    BadQueueNum,
    #[error("Failed binding vhost-user socket")]
    BindSocket(#[source] io::Error),
    #[error("Creating eventfd failed")]
    CreateEventFd(#[source] io::Error),
    #[error("Invalid descriptor table address")]
    DescriptorTableAddress,
    #[error("Signal used queue failed")]
    FailedSignalingUsedQueue(#[source] io::Error),
    #[error("Failed removing socket path")]
    RemoveSocketPath(#[source] io::Error),
    #[error("Connection to socket failed")]
    VhostUserConnect(#[source] VhostError),
    #[error("Get features failed")]
    VhostUserGetFeatures(#[source] VhostError),
    #[error("Get queue max number failed")]
    VhostUserGetQueueMaxNum(#[source] VhostError),
    #[error("Get protocol features failed")]
    VhostUserGetProtocolFeatures(#[source] VhostError),
    #[error("Backend does not support protocol features {0:#x}")]
    UnsupportedProtocolFeatures(u64),
    #[error(
        "The backend of restored device {id} does not offer virtio features {missing:#x} the snapshot acked"
    )]
    RestoredFeaturesUnsupported { id: String, missing: u64 },
    #[error(
        "The backend of restored device {id} reports {field} {backend}, but the snapshot holds {saved}"
    )]
    RestoredConfigMismatch {
        id: String,
        field: &'static str,
        saved: u64,
        backend: u64,
    },
    #[error("Protocol features {0:#x} saved without PROTOCOL_FEATURES acknowledged")]
    InconsistentProtocolFeatures(u64),
    #[error("Get vring base failed")]
    VhostUserGetVringBase(#[source] VhostError),
    #[error("Set owner failed")]
    VhostUserSetOwner(#[source] VhostError),
    #[error("Set features failed")]
    VhostUserSetFeatures(#[source] VhostError),
    #[error("Set protocol features failed")]
    VhostUserSetProtocolFeatures(#[source] VhostError),
    #[error("Set mem table failed")]
    VhostUserSetMemTable(#[source] VhostError),
    #[error(
        "Guest RAM is demand-paged, but the backend did not negotiate PAGEFAULT, so its accesses would bypass the fault handler"
    )]
    BackendServesNoFaults,
    #[error("Opening the backend's postcopy userfaultfd failed")]
    VhostUserPostcopyAdvise(#[source] VhostError),
    #[error("Telling the backend to register guest RAM with its userfaultfd failed")]
    VhostUserPostcopyListen(#[source] VhostError),
    #[error("Acknowledging the backend's postcopy memory table failed")]
    VhostUserPostcopyAck(#[source] VhostError),
    #[error("Handing the backend's userfaultfd to the fault handler failed")]
    AdoptBackendFaults(#[source] io::Error),
    #[error("Reading the page size of a guest memory region's backing failed")]
    BackingPageSize(#[source] io::Error),
    #[error(
        "Memory cannot be hot-plugged while guest RAM is demand-paged: the backend serves faults only on the memory tables the fault handler adopted"
    )]
    MemoryHotplugWhileDemandPaged,
    #[error("Set vring num failed")]
    VhostUserSetVringNum(#[source] VhostError),
    #[error("Set vring addr failed")]
    VhostUserSetVringAddr(#[source] VhostError),
    #[error("Set vring base failed")]
    VhostUserSetVringBase(#[source] VhostError),
    #[error("Set vring call failed")]
    VhostUserSetVringCall(#[source] VhostError),
    #[error("Set vring kick failed")]
    VhostUserSetVringKick(#[source] VhostError),
    #[error("Set vring enable failed")]
    VhostUserSetVringEnable(#[source] VhostError),
    #[error("Failed to read vhost eventfd")]
    VhostUserMemoryRegion(#[source] MmapError),
    #[error("Failed to create the frontend request handler from backend")]
    FrontendReqHandlerCreation(#[source] VhostUserError),
    #[error("Set backend request fd failed")]
    VhostUserSetBackendRequestFd(#[source] vhost::Error),
    #[error("Add memory region failed")]
    VhostUserAddMemReg(#[source] VhostError),
    #[error("Failed getting the configuration")]
    VhostUserGetConfig(#[source] VhostError),
    #[error("Failed setting the configuration")]
    VhostUserSetConfig(#[source] VhostError),
    #[error("Failed getting inflight shm log")]
    VhostUserGetInflight(#[source] VhostError),
    #[error("Failed setting inflight shm log")]
    VhostUserSetInflight(#[source] VhostError),
    #[error("Failed setting the log base")]
    VhostUserSetLogBase(#[source] VhostError),
    #[error("Invalid used address")]
    UsedAddress,
    #[error("Missing file descriptor for the region")]
    MissingRegionFd,
    #[error("Failed getting the available index")]
    GetAvailableIndex(#[source] QueueError),
    #[error("Failed getting the used index")]
    GetUsedIndex(#[source] QueueError),
    #[error("Failed to kick vhost-user vring")]
    VhostUserKickVring(#[source] io::Error),
    #[error("Migration is not supported by this vhost-user device")]
    MigrationNotSupported,
    #[error("Failed creating memfd")]
    MemfdCreate(#[source] io::Error),
    #[error("Failed truncating the file size to the expected size")]
    SetFileSize(#[source] io::Error),
    #[error("Failed to set the seals on the file")]
    SetSeals(#[source] io::Error),
    #[error("Failed creating new mmap region")]
    NewMmapRegion(#[source] MmapRegionError),
    #[error("Could not find the shm log region")]
    MissingShmLogRegion,
    #[error("Failed setting device state fd")]
    VhostUserSetDeviceStateFd(#[source] VhostError),
    #[error("Failed checking device state")]
    VhostUserCheckDeviceState(#[source] VhostError),
    #[error("Failed saving/restoring backend state")]
    SaveRestoreBackendState(#[source] io::Error),
    #[error("Vring bases count ({0}) does not match queue count ({1})")]
    VringBasesCountMismatch(usize, usize),
    #[error("Backend state and vring bases must both be present or both be absent")]
    InconsistentBackendState,
    #[error("Failed to create timerfd")]
    TimerFdCreate(#[source] io::Error),
    #[error("Failed to arm timerfd")]
    TimerFdArm(#[source] io::Error),
    #[error("Failed waiting on timerfd")]
    TimerFdWait(#[source] io::Error),
    #[error("Failed to create epoll instance")]
    EpollCreate(#[source] io::Error),
    #[error("Failed to add fd to epoll")]
    EpollCtl(#[source] io::Error),
    #[error("Failed waiting on epoll")]
    EpollWait(#[source] io::Error),
    #[error("Aborted vhost-user connect: kill event received")]
    ConnectKilled,
    #[error("Timed out waiting for vhost-user connection")]
    VhostUserConnectTimeout,
}
type Result<T> = result::Result<T, Error>;

fn io_error_is_connection_lost(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

fn vhost_user_error_is_transport_lost(error: &VhostUserError) -> bool {
    match error {
        VhostUserError::Disconnected
        | VhostUserError::PartialMessage
        | VhostUserError::SocketBroken(_)
        | VhostUserError::SocketConnect(_) => true,
        VhostUserError::SocketError(e) => io_error_is_connection_lost(e),
        _ => false,
    }
}

fn vhost_error_is_transport_lost(error: &VhostError) -> bool {
    match error {
        VhostError::VhostUserProtocol(e) => vhost_user_error_is_transport_lost(e),
        VhostError::IOError(e) => io_error_is_connection_lost(e),
        _ => false,
    }
}

impl Error {
    fn is_transport_lost(&self) -> bool {
        match self {
            Error::VhostUserConnect(_) => true,
            Error::VhostUserGetFeatures(e)
            | Error::VhostUserGetQueueMaxNum(e)
            | Error::VhostUserGetProtocolFeatures(e)
            | Error::VhostUserGetVringBase(e)
            | Error::VhostUserSetOwner(e)
            | Error::VhostUserSetFeatures(e)
            | Error::VhostUserSetProtocolFeatures(e)
            | Error::VhostUserSetMemTable(e)
            | Error::VhostUserSetVringNum(e)
            | Error::VhostUserSetVringAddr(e)
            | Error::VhostUserSetVringBase(e)
            | Error::VhostUserSetVringCall(e)
            | Error::VhostUserSetVringKick(e)
            | Error::VhostUserSetVringEnable(e)
            | Error::VhostUserSetBackendRequestFd(e)
            | Error::VhostUserAddMemReg(e)
            | Error::VhostUserGetConfig(e)
            | Error::VhostUserSetConfig(e)
            | Error::VhostUserGetInflight(e)
            | Error::VhostUserSetInflight(e)
            | Error::VhostUserSetLogBase(e)
            | Error::VhostUserSetDeviceStateFd(e)
            | Error::VhostUserCheckDeviceState(e)
            | Error::VhostUserPostcopyAdvise(e)
            | Error::VhostUserPostcopyListen(e)
            | Error::VhostUserPostcopyAck(e) => vhost_error_is_transport_lost(e),
            Error::FrontendReqHandlerCreation(e) => vhost_user_error_is_transport_lost(e),
            _ => false,
        }
    }
}

/// One of a vhost-user backend's mappings of guest RAM, as its postcopy
/// memory table reply reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendMapping {
    /// Where the backend mapped the region, in its address space.
    pub backend_addr: u64,
    /// Where this process maps the same region.
    pub vmm_addr: u64,
    /// The region's length in bytes.
    pub length: u64,
    /// The page size of the region's backing: a huge page size on
    /// hugetlbfs, else the base page size.
    pub page_size: u64,
}

/// Serves the faults vhost-user backends take on their own mappings of guest
/// RAM while it is demand-paged. A backend maps guest RAM outside the
/// VMM's userfaultfd, and its first touch of a page not yet served would
/// land a zero page in guest RAM that no later fault replaces, so each
/// backend registers its mappings with a userfaultfd of its own (the
/// vhost-user postcopy `PAGEFAULT` flow) and that userfaultfd is handed here.
pub trait BackendFaultHandler: Send + Sync {
    /// Serve the faults `device`'s backend takes on `mappings`, the
    /// memory table it mapped on vhost-user connection `connection`, an id
    /// unique within this process. `uffd`, the userfaultfd the backend
    /// registers every mapping on that connection with, is passed with the
    /// connection's first table only; a later table on the same connection
    /// adds its mappings to that userfaultfd's. Returns once the handler
    /// serves the mappings, or with its reason for refusing them, before
    /// which the backend must not be let touch guest RAM.
    fn adopt(
        &self,
        device: &str,
        connection: u64,
        mappings: &[BackendMapping],
        uffd: Option<BorrowedFd<'_>>,
    ) -> io::Result<()>;
}

/// A vhost-user device's backend faulting through a [`BackendFaultHandler`]:
/// set on a device created while guest RAM is demand-paged, for the
/// device's whole life, since every reconnect maps guest RAM afresh. Its
/// connections take the postcopy flow only until guest RAM settles.
#[derive(Clone)]
pub struct BackendFaults {
    /// The device id the handler names the backend by.
    pub device: String,
    /// The handler the backend's memory tables are handed to.
    pub handler: Arc<dyn BackendFaultHandler>,
    /// Whether guest RAM is still demand-paged, shared with the settle.
    pub paging: Arc<DemandPaging>,
}

/// Whether a VM's guest RAM is still demand-paged, as its vhost-user
/// connections see it: shared by every device created while it is, and by
/// the settle that ends demand paging, which flips it once and for good.
///
/// A memory table is sent with the lock held for reading: the postcopy way
/// while guest RAM is demand-paged, the plain way once it has settled. A
/// connection is registered here as it takes the postcopy flow, under the
/// same read lock. The settle holds the lock for writing through its
/// exchange with the fault handler and, once the handler answers settled,
/// through ending the postcopy flow on every registered connection. So no
/// table is in flight while the handler takes the backends' mappings off
/// their userfaultfds, no connection is left on the flow once guest RAM
/// is settled, and every table sent after takes the plain way.
#[derive(Default)]
pub struct DemandPaging {
    /// Whether guest RAM has settled.
    settled: RwLock<bool>,
    /// The backend connections on the postcopy flow, by the id each is
    /// handed to the fault handler under, until the settle ends the flow
    /// on them or they are dropped.
    connections: Mutex<BTreeMap<u64, Frontend>>,
}

impl DemandPaging {
    /// Whether guest RAM has settled.
    pub fn settled(&self) -> bool {
        *self.settled.read().unwrap()
    }

    /// Settle guest RAM: run `exchange`, the settle exchange with the fault
    /// handler, with no memory table in flight, and once it answers that
    /// guest RAM is settled, end the postcopy flow on every connection on it
    /// and record that for good. Returns whether guest RAM is settled; once
    /// it is, without running `exchange` again.
    ///
    /// A connection already lost has nothing left to end: its backend's
    /// userfaultfd went with it. A backend that refuses `POSTCOPY_END`, or
    /// answers it any other way than with an acknowledgement, may still be
    /// registered for missing faults on guest RAM that nothing serves any
    /// more, and fails the settle with [`SettleError::EndRefused`], leaving
    /// guest RAM recorded as demand-paged. Shutting its connection down
    /// instead would leave the device to reconnect only if its worker is
    /// running, which it is not once the guest has reset the device, so the
    /// caller is left to fail the VM.
    pub fn settle<E>(
        &self,
        exchange: impl FnOnce() -> result::Result<bool, E>,
    ) -> result::Result<bool, SettleError<E>> {
        let mut settled = self.settled.write().unwrap();
        if *settled {
            return Ok(true);
        }
        if !exchange().map_err(SettleError::Exchange)? {
            return Ok(false);
        }
        let connections = mem::take(&mut *self.connections.lock().unwrap());
        for (connection, mut frontend) in connections {
            match frontend.postcopy_end() {
                Ok(()) => {}
                Err(e) if vhost_error_is_transport_lost(&e) => warn!(
                    "Vhost-user connection {connection} was lost before the settle ended its postcopy flow: {e:?}"
                ),
                Err(error) => return Err(SettleError::EndRefused { connection, error }),
            }
        }
        *settled = true;
        Ok(true)
    }

    /// Hold off a settle while a memory table is sent. The guard reads
    /// whether guest RAM has settled.
    fn hold(&self) -> RwLockReadGuard<'_, bool> {
        self.settled.read().unwrap()
    }

    /// Register `frontend`'s connection as on the postcopy flow, for the
    /// settle to end it, under the guard of [`Self::hold`] that found guest
    /// RAM still demand-paged. The registration names the connection to the
    /// fault handler and lasts until it is dropped.
    fn register(
        self: &Arc<Self>,
        held: &RwLockReadGuard<'_, bool>,
        frontend: &Frontend,
    ) -> PostcopyConnection {
        debug_assert!(
            !**held,
            "a connection takes the postcopy flow only before the settle"
        );
        /// The id the next connection to take the postcopy flow is named
        /// by, for the life of the process.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        self.connections
            .lock()
            .unwrap()
            .insert(id, frontend.clone());
        PostcopyConnection {
            id,
            paging: Arc::clone(self),
        }
    }
}

/// Why [`DemandPaging::settle`] failed.
#[derive(Debug, Error)]
pub enum SettleError<E> {
    /// The settle exchange with the fault handler failed, and nothing
    /// changed.
    #[error("the settle exchange with the fault handler failed")]
    Exchange(#[source] E),
    /// The fault handler settled guest RAM, but the backend of vhost-user
    /// connection `connection` did not acknowledge the end of its postcopy
    /// flow, so it may still be registered for missing faults that nothing
    /// serves.
    #[error("the backend of vhost-user connection {connection} did not end its postcopy flow")]
    EndRefused {
        connection: u64,
        #[source]
        error: VhostError,
    },
}

/// A backend connection's place on the postcopy flow, registered with the
/// [`DemandPaging`] whose settle ends it. Dropped with the connection,
/// which takes it off the register.
pub(crate) struct PostcopyConnection {
    /// The id the connection is handed to the fault handler under.
    id: u64,
    paging: Arc<DemandPaging>,
}

impl PostcopyConnection {
    /// The id the connection is handed to the fault handler under.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for PostcopyConnection {
    fn drop(&mut self) {
        self.paging.connections.lock().unwrap().remove(&self.id);
    }
}

pub const DEFAULT_VIRTIO_FEATURES: u64 = (1 << VIRTIO_F_RING_INDIRECT_DESC)
    | (1 << VIRTIO_F_RING_EVENT_IDX)
    | (1 << VIRTIO_F_VERSION_1)
    | (1 << VIRTIO_F_IN_ORDER)
    | (1 << VIRTIO_F_ORDER_PLATFORM)
    | (1 << VIRTIO_F_NOTIFICATION_DATA)
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    | VhostUserVirtioFeatures::LOG_ALL.bits();

const HUP_CONNECTION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const BACKEND_REQ_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
const RESUME_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

#[derive(Default)]
pub struct Inflight {
    pub info: VhostUserInflight,
    pub fd: Option<File>,
}

pub struct VhostUserEpollHandler<S: VhostUserFrontendReqHandler> {
    pub vu: Arc<Mutex<VhostUserHandle>>,
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub queues: Vec<(u16, Queue, EventFd)>,
    pub virtio_interrupt: Arc<dyn VirtioInterrupt>,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub socket_path: String,
    pub server: bool,
    pub backend_req_handler: Option<FrontendReqHandler<S>>,
    pub inflight: Option<Inflight>,
    /// Flag set by the worker when the vhost-user backend is no longer reachable.
    pub disconnected: Arc<AtomicBool>,
    pub resume_evt: EventFd,
    /// Carried to every reconnection: see [`VhostUserCommon::faults`].
    pub faults: Option<BackendFaults>,
}

impl<S: VhostUserFrontendReqHandler> VhostUserEpollHandler<S> {
    pub fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event_custom(
            self.vu.lock().unwrap().socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        if let Some(backend_req_handler) = &self.backend_req_handler {
            helper.add_event(backend_req_handler.as_raw_fd(), BACKEND_REQ_EVENT)?;
        }

        helper.add_event(self.resume_evt.as_raw_fd(), RESUME_EVENT)?;

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn reconnect(&mut self, helper: &mut EpollHelper) -> result::Result<(), EpollHelperError> {
        let result = self.reconnect_inner(helper);
        if result.is_err() {
            // If reconnect fails, mark disconnected to avoid repeated failed socket calls.
            self.disconnected.store(true, Ordering::Relaxed);
        }
        result
    }

    fn reconnect_inner(
        &mut self,
        helper: &mut EpollHelper,
    ) -> result::Result<(), EpollHelperError> {
        helper.del_event_custom(
            self.vu.lock().unwrap().socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        let queues = self
            .queues
            .iter()
            .map(|(i, q, e)| (*i, vm_virtio::clone_queue(q), e.try_clone().unwrap()))
            .collect::<Vec<_>>();

        let mut vhost_user = match VhostUserHandle::connect_vhost_user(
            self.server,
            &self.socket_path,
            self.queues.len() as u64,
            true,
            &self.kill_evt,
            self.faults.as_ref(),
            |vhost_user| {
                vhost_user.reinitialize_vhost_user(
                    self.mem.memory().deref(),
                    &queues,
                    self.virtio_interrupt.as_ref(),
                    self.acked_features,
                    self.acked_protocol_features,
                    &self.backend_req_handler,
                    self.inflight.as_mut(),
                )
            },
        ) {
            Ok(vu) => vu,
            // Kill event fired during the reconnect retry loop; abandon the
            // reconnect attempt. The EpollHelper observes the same kill
            // event and will tear down on its next iteration.
            Err(Error::ConnectKilled) => return Ok(()),
            Err(e) => {
                return Err(EpollHelperError::IoError(io::Error::other(format!(
                    "failed reconnecting vhost-user backend for socket {}: {e:?}",
                    self.socket_path
                ))));
            }
        };

        helper.add_event_custom(
            vhost_user.socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        // Update vhost-user reference
        let mut vu = self.vu.lock().unwrap();
        *vu = vhost_user;

        Ok(())
    }
}

impl<S: VhostUserFrontendReqHandler> EpollHelperHandler for VhostUserEpollHandler<S> {
    fn handle_event(
        &mut self,
        helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        let result = match ev_type {
            HUP_CONNECTION_EVENT => {
                info!(
                    "vhost-user backend for socket {} disconnected, attempting reconnection",
                    self.socket_path
                );
                self.reconnect(helper).map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "failed to reconnect vhost-user backend for socket {}: {e:?}",
                        self.socket_path
                    ))
                })
            }
            BACKEND_REQ_EVENT => {
                if let Some(backend_req_handler) = self.backend_req_handler.as_mut() {
                    backend_req_handler
                        .handle_request()
                        .map(|_| ())
                        .map_err(|e| {
                            EpollHelperError::HandleEvent(anyhow!(
                                "Failed to handle request from vhost-user backend: {e:?}"
                            ))
                        })
                } else {
                    Ok(())
                }
            }
            RESUME_EVENT => {
                let _ = self.resume_evt.read();
                self.vu
                    .lock()
                    .unwrap()
                    .resume(
                        &self.mem.memory(),
                        &self.queues,
                        self.virtio_interrupt.as_ref(),
                        self.acked_features,
                        &self.backend_req_handler,
                        self.inflight.as_mut(),
                    )
                    .map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "failed to resume vhost-user backend for socket {}: {e:?}",
                            self.socket_path
                        ))
                    })
            }
            _ => Err(EpollHelperError::HandleEvent(anyhow!(
                "Unknown event for vhost-user thread"
            ))),
        };

        // If the backend hits and error it is unusable from this point on.
        if result.is_err() {
            self.disconnected.store(true, Ordering::Relaxed);
        }
        result
    }
}

/// Common snapshot state for all vhost-user device types.
///
/// Generic over `C` which is the device-specific config type
/// (e.g. VirtioBlockConfig, VirtioFsConfig, VirtioNetConfig).
/// Devices without a config type use `()`.
#[derive(Default, Serialize, Deserialize)]
pub struct VhostUserState<C> {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: C,
    pub acked_protocol_features: u64,
    pub vu_num_queues: usize,
    #[serde(default)]
    pub vring_bases: Option<Vec<u64>>,
    #[serde(default)]
    pub backend_state: Option<Vec<u8>>,
}

impl<C> VhostUserState<C> {
    pub fn validate(&self) -> Result<()> {
        if self.backend_state.is_some() != self.vring_bases.is_some() {
            return Err(Error::InconsistentBackendState);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct VhostUserCommon {
    pub virtio_common: VirtioCommon,
    pub vu: Option<Arc<Mutex<VhostUserHandle>>>,
    pub guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    pub acked_protocol_features: u64,
    pub socket_path: String,
    pub vu_num_queues: usize,
    pub migration_started: bool,
    pub server: bool,
    pub vring_bases: Option<Vec<u64>>,
    /// Indicates that the backend is no longer reachable. Shared with EPollHandler.
    pub disconnected: Arc<AtomicBool>,
    saved_dirty_log: Option<MemoryRangeTable>,
    dirty_logging: bool,
    resume_evt: Option<EventFd>,
    /// Set on a device created while guest RAM is demand-paged: until it
    /// settles, the backend faults through the handler, on every connection.
    pub faults: Option<BackendFaults>,
}

impl VhostUserCommon {
    #[expect(clippy::too_many_arguments)]
    pub fn activate<T: VhostUserFrontendReqHandler>(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        queues: &[(u16, Queue, EventFd)],
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        acked_features: u64,
        backend_req_handler: Option<FrontendReqHandler<T>>,
        kill_evt: EventFd,
        pause_evt: EventFd,
    ) -> result::Result<VhostUserEpollHandler<T>, ActivateError> {
        self.guest_memory = Some(mem.clone());

        if self.disconnected.load(Ordering::Relaxed) {
            warn!(
                "Not activating disconnected vhost-user device for socket {}",
                self.socket_path
            );
            return Err(ActivateError::BadActivate);
        }

        let mut inflight: Option<Inflight> =
            if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() != 0
            {
                Some(Inflight::default())
            } else {
                None
            };

        if self.vu.is_none() {
            error!("Missing vhost-user handle for socket {}", self.socket_path);
            return Err(ActivateError::BadActivate);
        }
        let vu = self.vu.as_ref().unwrap();
        let queues = queues
            .iter()
            .map(|(i, q, e)| (*i, vm_virtio::clone_queue(q), e.try_clone().unwrap()))
            .collect::<Vec<_>>();
        let vring_bases = self.vring_bases.take();
        vu.lock()
            .unwrap()
            .setup_vhost_user(
                &mem.memory(),
                &queues,
                interrupt_cb.as_ref(),
                acked_features,
                &backend_req_handler,
                inflight.as_mut(),
                vring_bases.as_deref(),
            )
            .map_err(ActivateError::VhostUserSetup)?;

        let resume_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(ActivateError::CreateEventFd)?;
        self.resume_evt = Some(
            resume_evt
                .try_clone()
                .map_err(ActivateError::CloneEventFd)?,
        );

        // A device asked to log its writes before it was activated (one
        // hot-plugged while the VM's devices log) starts logging here,
        // before the guest can hand it a request.
        if self.dirty_logging {
            vu.lock()
                .unwrap()
                .start_dirty_log(mem.memory().last_addr().raw_value())
                .map_err(ActivateError::VhostUserSetup)?;
        }

        Ok(VhostUserEpollHandler {
            vu: Arc::clone(vu),
            mem,
            kill_evt,
            pause_evt,
            queues,
            virtio_interrupt: interrupt_cb,
            acked_features,
            acked_protocol_features: self.acked_protocol_features,
            socket_path: self.socket_path.clone(),
            server: self.server,
            backend_req_handler,
            inflight,
            disconnected: Arc::clone(&self.disconnected),
            resume_evt,
            faults: self.faults.clone(),
        })
    }

    /// Like `VirtioCommon::spawn_worker`, but on failure also runs
    /// `self.reset(id)` to tear down the vhost-user backend.
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_worker<F>(
        &mut self,
        id: &str,
        seccomp_action: &SeccompAction,
        thread_type: Thread,
        exit_evt: &EventFd,
        device_status: Arc<AtomicU8>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        f: F,
    ) -> result::Result<(), ActivateError>
    where
        F: FnOnce() -> result::Result<(), EpollHelperError> + Send + 'static,
    {
        if let Err(e) = self.virtio_common.spawn_worker(
            id,
            seccomp_action,
            thread_type,
            exit_evt,
            device_status,
            interrupt_cb,
            f,
        ) {
            self.reset(id);
            return Err(e);
        }
        Ok(())
    }

    pub fn reset(&mut self, id: &str) {
        // Resume the virtio thread if it was paused. Reset must always
        // converge to fresh state, so backend resume / reset failures are
        // logged but don't skip the rest of the teardown.
        if self.virtio_common.pause_evt.take().is_some()
            && let Err(e) = self.virtio_common.resume()
        {
            error!("Failed to resume paused device during reset: {e:?}");
        }

        // Skip reset_vhost_user if the backend is not connected.
        if !self.disconnected.load(Ordering::Relaxed)
            && let Some(vu) = &self.vu
            && let Err(e) = vu.lock().unwrap().reset_vhost_user()
        {
            if e.is_transport_lost() {
                warn!(
                    "Failed to reset vhost-user daemon for socket {}: {e:?}; \
                     marking device as disconnected",
                    self.socket_path
                );
                self.disconnected.store(true, Ordering::Relaxed);
            } else {
                warn!(
                    "Failed to reset vhost-user daemon for socket {}: {e:?}",
                    self.socket_path
                );
            }
        }

        self.virtio_common.reset();

        event!("virtio-device", "reset", "id", id);
    }

    fn memory_update_error(&self, source: Error) -> crate::Error {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() != 0
        {
            crate::Error::VhostUserAddMemoryRegion(source)
        } else {
            crate::Error::VhostUserUpdateMemory(source)
        }
    }

    pub fn shutdown(&mut self) {
        // Join the workers so they drop their Arc<VhostUserHandle> and the
        // socket closes, letting the migration destination reconnect.
        self.virtio_common.wait_for_epoll_threads();

        // Remove socket path if needed
        if self.server {
            let _ = remove_file(&self.socket_path);
        }

        // Drop the vhost-user handle
        self.vu = None;
    }

    fn add_memory_region_internal(&self, region: &Arc<GuestRegionMmap>) -> Result<()> {
        if let Some(vu) = &self.vu {
            if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                != 0
            {
                return vu.lock().unwrap().add_memory_region(region);
            } else if let Some(guest_memory) = &self.guest_memory {
                return vu
                    .lock()
                    .unwrap()
                    .update_mem_table(guest_memory.memory().deref());
            }
        }

        Ok(())
    }

    pub fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> result::Result<(), crate::Error> {
        // A backend listening for postcopy cannot take ADD_MEM_REG, and
        // nothing would serve its faults on the region anyway.
        if self
            .faults
            .as_ref()
            .is_some_and(|faults| !faults.paging.settled())
        {
            return Err(self.memory_update_error(Error::MemoryHotplugWhileDemandPaged));
        }

        if self.disconnected.load(Ordering::Relaxed) {
            warn!(
                "Skipping add memory region on disconnected dev with socket: {}",
                self.socket_path
            );
        }

        if let Err(e) = self.add_memory_region_internal(region) {
            if e.is_transport_lost() {
                warn!(
                    "Failed updating memory on vhost-user backend for socket {}: {e:?}; \
                     marking device as disconnected",
                    self.socket_path
                );
                self.disconnected.store(true, Ordering::Relaxed);
            } else {
                warn!(
                    "Failed updating memory on vhost-user backend for socket {}: {e:?}",
                    self.socket_path
                );
            }
            return Err(self.memory_update_error(e));
        }
        Ok(())
    }

    pub fn pause(&mut self) -> result::Result<(), MigratableError> {
        if self.disconnected.load(Ordering::Relaxed) {
            return Err(MigratableError::DeviceDisconnected(
                self.socket_path.clone(),
            ));
        }

        if let Some(vu) = &self.vu
            && let Err(e) = vu.lock().unwrap().pause_vhost_user()
        {
            if e.is_transport_lost() {
                self.disconnected.store(true, Ordering::Relaxed);
                return Err(MigratableError::DeviceDisconnected(
                    self.socket_path.clone(),
                ));
            }

            return Err(MigratableError::Pause(anyhow!(
                "Error pausing vhost-user backend for socket {}: {e:?}",
                self.socket_path
            )));
        }
        Ok(())
    }

    fn resume_internal(&mut self) -> result::Result<(), MigratableError> {
        if self.disconnected.load(Ordering::Relaxed) {
            return Err(MigratableError::DeviceDisconnected(
                self.socket_path.clone(),
            ));
        }

        let Some(evt) = &self.resume_evt else {
            return Ok(());
        };

        evt.write(1).map_err(|e| {
            MigratableError::Resume(anyhow!(
                "Error signaling vhost-user resume for socket {}: {e}",
                self.socket_path
            ))
        })
    }

    pub fn resume(&mut self) -> result::Result<(), MigratableError> {
        let ret = self.resume_internal();

        // Always run the interrupt loop so workers don't get stuck.
        for i in 0..self.vu_num_queues {
            self.virtio_common
                .trigger_interrupt(crate::VirtioInterruptType::Queue(i as u16))
                .ok();
        }

        ret
    }

    pub fn state<C: Default>(
        &self,
        config: C,
    ) -> result::Result<VhostUserState<C>, MigratableError> {
        let mut state = VhostUserState {
            avail_features: self.virtio_common.avail_features,
            acked_features: self.virtio_common.acked_features,
            config,
            acked_protocol_features: self.acked_protocol_features,
            vu_num_queues: self.vu_num_queues,
            ..Default::default()
        };

        if let Some(vu) = &self.vu {
            let mut vu_locked = vu.lock().unwrap();
            if vu_locked.supports_device_state() {
                let (backend_state, vring_bases) = vu_locked.save_backend_state().map_err(|e| {
                    MigratableError::Snapshot(anyhow!("Failed saving backend state: {e:?}"))
                })?;
                state.backend_state = Some(backend_state);
                state.vring_bases = Some(vring_bases);
            }
        }

        Ok(state)
    }

    pub fn snapshot<T>(&mut self, state: &T) -> result::Result<Snapshot, MigratableError>
    where
        T: Serialize,
    {
        let snapshot = Snapshot::new_from_state(state)?;

        if self.migration_started {
            // Precopy migration may enable dirty logging.
            if self.dirty_logging {
                self.saved_dirty_log = Some(self.dirty_log()?);
            }
            self.shutdown();
        }

        Ok(snapshot)
    }

    /// Start logging the guest memory the backend writes. A device not yet
    /// activated has written nothing; it starts logging when it activates.
    pub fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            if self.guest_memory.is_none() {
                self.dirty_logging = true;
                return Ok(());
            }
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock()
                    .unwrap()
                    .start_dirty_log(last_ram_addr)
                    .map_err(|e| {
                        MigratableError::StartDirtyLog(anyhow!(
                            "Error starting migration for vhost-user backend: {e:?}"
                        ))
                    })?;
                self.dirty_logging = true;
                Ok(())
            } else {
                Err(MigratableError::StartDirtyLog(anyhow!(
                    "Missing guest memory"
                )))
            }
        } else {
            Ok(())
        }
    }

    pub fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu
            && self.guest_memory.is_some()
        {
            vu.lock().unwrap().stop_dirty_log().map_err(|e| {
                MigratableError::StopDirtyLog(anyhow!(
                    "Error stopping migration for vhost-user backend: {e:?}"
                ))
            })?;
        }

        self.dirty_logging = false;
        Ok(())
    }

    /// The guest memory the backend wrote since the last call. A device
    /// not yet activated has written none.
    pub fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock().unwrap().dirty_log(last_ram_addr).map_err(|e| {
                    MigratableError::DirtyLog(anyhow!(
                        "Error retrieving dirty ranges from vhost-user backend: {e:?}"
                    ))
                })
            } else {
                Ok(MemoryRangeTable::default())
            }
        } else {
            Ok(self.saved_dirty_log.take().unwrap_or_default())
        }
    }

    pub fn notify_started_migration(&mut self) -> result::Result<(), MigratableError> {
        self.migration_started = true;
        Ok(())
    }

    pub fn notify_failed_migration(&mut self) -> result::Result<(), MigratableError> {
        self.migration_started = false;
        Ok(())
    }

    pub fn notify_completed_migration(&mut self) -> result::Result<(), MigratableError> {
        self.migration_started = false;
        self.dirty_logging = false;

        // Make sure the device thread is killed in order to prevent from
        // reconnections to the socket.
        if let Some(workers) = self.virtio_common.workers.as_ref() {
            workers.signal_exit().map_err(|e| {
                MigratableError::CompleteMigration(anyhow!(
                    "Error killing vhost-user thread: {e:?}"
                ))
            })?;
        }

        // Drop the vhost-user handler to avoid further calls to fail because
        // the connection with the backend has been closed.
        self.vu = None;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    use vhost::vhost_user::message::{FrontendReq, VhostUserHeaderFlag};
    use vm_memory::{FileOffset, GuestAddress};
    use vm_migration::Snapshottable;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::vsock::tests::NoopVirtioInterrupt;
    use crate::{VIRTIO_F_ACCESS_PLATFORM, VirtioDevice};

    /// A fault handler for tests whose backends never get a memory table.
    struct Unused;

    impl BackendFaultHandler for Unused {
        fn adopt(
            &self,
            _: &str,
            _: u64,
            _: &[BackendMapping],
            _: Option<BorrowedFd<'_>>,
        ) -> io::Result<()> {
            Err(io::Error::other("no memory table is sent"))
        }
    }

    fn read_request(stream: &mut UnixStream, expected_request: FrontendReq) -> Vec<u8> {
        let mut header = [0u8; 12];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(
            u32::from_ne_bytes(header[0..4].try_into().unwrap()),
            u32::from(expected_request)
        );
        let size = u32::from_ne_bytes(header[8..12].try_into().unwrap()) as usize;
        let mut payload = vec![0; size];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    #[test]
    fn connect_retries_get_features_disconnect_with_fresh_socket() {
        let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-reconnect-").unwrap();
        let socket_path = temp_dir.as_path().join("backend.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let backend = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            assert!(read_request(&mut first, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut first, FrontendReq::GET_FEATURES).is_empty());
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            assert!(read_request(&mut second, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut second, FrontendReq::GET_FEATURES).is_empty());

            let mut reply = Vec::with_capacity(20);
            reply.extend_from_slice(&u32::from(FrontendReq::GET_FEATURES).to_ne_bytes());
            reply.extend_from_slice(&(VhostUserHeaderFlag::REPLY.bits() | 1).to_ne_bytes());
            reply.extend_from_slice(&8u32.to_ne_bytes());
            reply.extend_from_slice(&0u64.to_ne_bytes());
            second.write_all(&reply).unwrap();
        });

        let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        VhostUserHandle::connect_vhost_user(
            false,
            socket_path.to_str().unwrap(),
            1,
            false,
            &kill_evt,
            None,
            |_| Ok(()),
        )
        .unwrap();

        backend.join().unwrap();
    }

    #[test]
    fn access_platform_is_preserved_in_guest_features() {
        let access_platform = 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        for enabled in [false, true] {
            for backend_features in [0, access_platform] {
                let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-features-").unwrap();
                let socket_path = temp_dir.as_path().join("backend.sock");
                let listener = UnixListener::bind(&socket_path).unwrap();
                let backend = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
                    assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
                    for value in [
                        u32::from(FrontendReq::GET_FEATURES),
                        VhostUserHeaderFlag::REPLY.bits() | 1,
                        8,
                    ] {
                        stream.write_all(&value.to_ne_bytes()).unwrap();
                    }
                    stream.write_all(&backend_features.to_ne_bytes()).unwrap();
                });

                let mut device = GenericVhostUser::new(
                    "test".to_string(),
                    socket_path.to_str().unwrap(),
                    vec![256],
                    vm_virtio::VirtioDeviceType::Fs as u32,
                    None,
                    SeccompAction::Allow,
                    EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    enabled,
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(device.features() & access_platform != 0, enabled);
                device.ack_features(access_platform);
                let state: VhostUserState<()> = device.snapshot().unwrap().to_state().unwrap();
                assert_eq!(state.avail_features, device.features());
                assert_eq!(state.acked_features & access_platform != 0, enabled);
                backend.join().unwrap();
            }
        }
    }

    #[test]
    fn access_platform_is_not_sent_to_backend() {
        let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-features-").unwrap();
        let socket_path = temp_dir.as_path().join("backend.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let backend = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
            for value in [
                u32::from(FrontendReq::GET_FEATURES),
                VhostUserHeaderFlag::REPLY.bits() | 1,
                8,
            ] {
                stream.write_all(&value.to_ne_bytes()).unwrap();
            }
            let features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_F_ACCESS_PLATFORM);
            stream.write_all(&features.to_ne_bytes()).unwrap();
            assert_eq!(
                read_request(&mut stream, FrontendReq::SET_FEATURES),
                (1u64 << VIRTIO_F_VERSION_1).to_ne_bytes()
            );
            assert_eq!(
                read_request(&mut stream, FrontendReq::SET_MEM_TABLE).len(),
                40
            );
        });

        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temp_dir.as_path().join("memory"))
            .unwrap();
        file.set_len(0x1000).unwrap();
        let mem = GuestMemoryMmap::from_ranges_with_files(&[(
            GuestAddress(0),
            0x1000,
            Some(FileOffset::new(file, 0)),
        )])
        .unwrap();
        let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut vu = VhostUserHandle::connect_vhost_user(
            false,
            socket_path.to_str().unwrap(),
            1,
            false,
            &kill_evt,
            None,
            |_| Ok(()),
        )
        .unwrap();
        struct BackendReqHandler;
        impl VhostUserFrontendReqHandler for BackendReqHandler {}
        vu.setup_vhost_user::<BackendReqHandler>(
            &mem,
            &[],
            &NoopVirtioInterrupt {},
            (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_F_ACCESS_PLATFORM),
            &None,
            None,
            None,
        )
        .unwrap();
        backend.join().unwrap();
    }

    /// A demand-paged restore requires PAGEFAULT of every backend: it is
    /// added for a backend that offers it, though the snapshot predates it,
    /// and a backend that does not offer it is refused before any protocol
    /// settings are sent.
    #[test]
    fn demand_paged_restore_requires_pagefault() {
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let mq = VhostUserProtocolFeatures::MQ.bits();
        let pagefault = VhostUserProtocolFeatures::PAGEFAULT.bits();
        for available in [mq | pagefault, mq] {
            let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-pagefault-").unwrap();
            let socket_path = temp_dir.as_path().join("backend.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let backend = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
                for (request, value) in [
                    (FrontendReq::GET_FEATURES, protocol_features),
                    (FrontendReq::GET_PROTOCOL_FEATURES, available),
                ] {
                    assert!(read_request(&mut stream, request).is_empty());
                    for field in [u32::from(request), VhostUserHeaderFlag::REPLY.bits() | 1, 8] {
                        stream.write_all(&field.to_ne_bytes()).unwrap();
                    }
                    stream.write_all(&value.to_ne_bytes()).unwrap();
                }
                if available & pagefault != 0 {
                    assert_eq!(
                        read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                        (mq | pagefault).to_ne_bytes()
                    );
                }
                assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
            });

            let faults = BackendFaults {
                device: "_disk0".to_owned(),
                handler: Arc::new(Unused),
                paging: Arc::new(DemandPaging::default()),
            };
            let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let result = VhostUserHandle::connect_vhost_user(
                false,
                socket_path.to_str().unwrap(),
                1,
                false,
                &kill_evt,
                Some(&faults),
                |vu| vu.set_protocol_features_vhost_user(protocol_features, mq),
            );
            match result {
                Ok(vu) => {
                    assert_ne!(available & pagefault, 0);
                    drop(vu);
                }
                Err(Error::BackendServesNoFaults) => assert_eq!(available & pagefault, 0),
                Err(e) => panic!("unexpected error: {e:?}"),
            }
            backend.join().unwrap();
        }
    }

    /// PAGEFAULT is sent to a backend only while guest RAM is demand-paged
    /// and never kept in the protocol features a device saves: a negotiation
    /// that sent it returns the features without it, and a restore of saved
    /// features carrying it neither sends it nor requires it of a backend
    /// when guest RAM is not demand-paged, the backend of a device created
    /// while it was, which reconnects after the settle, included.
    #[test]
    fn pagefault_is_negotiated_per_connection_and_never_saved() {
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let mq = VhostUserProtocolFeatures::MQ.bits();
        let pagefault = VhostUserProtocolFeatures::PAGEFAULT.bits();
        // (device created while demand-paged, still demand-paged, offered
        // by the backend, sent to it)
        for (relayed, demand_paged, available, sent) in [
            (true, true, mq | pagefault, mq | pagefault),
            (false, false, mq, mq),
            (true, false, mq, mq),
        ] {
            let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-pagefault-").unwrap();
            let socket_path = temp_dir.as_path().join("backend.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let backend = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
                for (request, value) in [
                    (FrontendReq::GET_FEATURES, protocol_features),
                    (FrontendReq::GET_PROTOCOL_FEATURES, available),
                ] {
                    assert!(read_request(&mut stream, request).is_empty());
                    for field in [u32::from(request), VhostUserHeaderFlag::REPLY.bits() | 1, 8] {
                        stream.write_all(&field.to_ne_bytes()).unwrap();
                    }
                    stream.write_all(&value.to_ne_bytes()).unwrap();
                }
                assert_eq!(
                    read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                    sent.to_ne_bytes()
                );
                assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
            });

            let faults = relayed.then(|| BackendFaults {
                device: "_disk0".to_owned(),
                handler: Arc::new(Unused),
                paging: Arc::new(DemandPaging::default()),
            });
            if let Some(faults) = &faults
                && !demand_paged
            {
                faults.paging.settle(|| Ok::<_, ()>(true)).unwrap();
            }
            let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let mut negotiated = None;
            let vu = VhostUserHandle::connect_vhost_user(
                false,
                socket_path.to_str().unwrap(),
                1,
                false,
                &kill_evt,
                faults.as_ref(),
                |vu| {
                    if demand_paged {
                        negotiated = Some(vu.negotiate_features_vhost_user(
                            protocol_features,
                            VhostUserProtocolFeatures::MQ,
                        )?);
                        Ok(())
                    } else {
                        vu.set_protocol_features_vhost_user(protocol_features, mq | pagefault)
                    }
                },
            )
            .unwrap();
            if demand_paged {
                assert_eq!(negotiated, Some((protocol_features, mq)));
            }
            drop(vu);
            backend.join().unwrap();
        }
    }

    /// Memory hot-plug is refused up front while guest RAM is demand-paged,
    /// with or without CONFIGURE_MEM_SLOTS, before anything reaches the
    /// backend, and taken once it has settled.
    #[test]
    fn memory_hotplug_is_refused_while_demand_paged() {
        let region = Arc::new(
            GuestRegionMmap::new(
                crate::MmapRegion::new(0x1000).unwrap(),
                GuestAddress(0x1_0000_0000),
            )
            .unwrap(),
        );
        for acked_protocol_features in [0, VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()] {
            let paging = Arc::new(DemandPaging::default());
            let mut common = VhostUserCommon {
                acked_protocol_features,
                faults: Some(BackendFaults {
                    device: "_disk0".to_owned(),
                    handler: Arc::new(Unused),
                    paging: Arc::clone(&paging),
                }),
                ..Default::default()
            };
            match common.add_memory_region(&region) {
                Err(crate::Error::VhostUserUpdateMemory(Error::MemoryHotplugWhileDemandPaged)) => {
                    assert_eq!(acked_protocol_features, 0);
                }
                Err(crate::Error::VhostUserAddMemoryRegion(
                    Error::MemoryHotplugWhileDemandPaged,
                )) => assert_ne!(acked_protocol_features, 0),
                other => panic!("unexpected hot-plug result: {other:?}"),
            }

            paging.settle(|| Ok::<_, ()>(true)).unwrap();
            common.add_memory_region(&region).unwrap();
        }
    }

    #[test]
    fn restored_protocol_features_must_be_supported() {
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let mq = VhostUserProtocolFeatures::MQ.bits();
        let config = VhostUserProtocolFeatures::CONFIG.bits();
        for (saved, available) in [(mq, mq | config), (mq, config), (1u64 << 63, mq)] {
            let missing = saved & !available;
            let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-protocol-").unwrap();
            let socket_path = temp_dir.as_path().join("backend.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let backend = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
                for (request, value) in [
                    (FrontendReq::GET_FEATURES, protocol_features),
                    (FrontendReq::GET_PROTOCOL_FEATURES, available),
                ] {
                    assert!(read_request(&mut stream, request).is_empty());
                    for field in [u32::from(request), VhostUserHeaderFlag::REPLY.bits() | 1, 8] {
                        stream.write_all(&field.to_ne_bytes()).unwrap();
                    }
                    stream.write_all(&value.to_ne_bytes()).unwrap();
                }
                if missing == 0 {
                    assert_eq!(
                        read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                        saved.to_ne_bytes()
                    );
                }
                // An incompatible connection must close before sending any
                // protocol settings, device state, or memory addresses.
                assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
            });

            let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let result = VhostUserHandle::connect_vhost_user(
                false,
                socket_path.to_str().unwrap(),
                1,
                false,
                &kill_evt,
                None,
                |vu| vu.set_protocol_features_vhost_user(protocol_features, saved),
            );
            match result {
                Ok(vu) => {
                    assert_eq!(missing, 0);
                    drop(vu);
                }
                Err(Error::UnsupportedProtocolFeatures(bits)) => {
                    assert_ne!(missing, 0);
                    assert_eq!(bits, missing);
                }
                Err(err) => panic!("Unexpected negotiation error: {err}"),
            }
            backend.join().unwrap();
        }
    }

    #[test]
    fn restored_protocol_features_require_protocol_features_bit() {
        for saved in [0, VhostUserProtocolFeatures::MQ.bits()] {
            let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-protocol-").unwrap();
            let socket_path = temp_dir.as_path().join("backend.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let backend = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
                assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
                for field in [
                    u32::from(FrontendReq::GET_FEATURES),
                    VhostUserHeaderFlag::REPLY.bits() | 1,
                    8,
                ] {
                    stream.write_all(&field.to_ne_bytes()).unwrap();
                }
                stream.write_all(&0u64.to_ne_bytes()).unwrap();
                // Protocol negotiation must not occur without PROTOCOL_FEATURES.
                assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
            });

            let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let result = VhostUserHandle::connect_vhost_user(
                false,
                socket_path.to_str().unwrap(),
                1,
                false,
                &kill_evt,
                None,
                |vu| vu.set_protocol_features_vhost_user(0, saved),
            );
            match result {
                Ok(vu) => {
                    assert_eq!(saved, 0);
                    drop(vu);
                }
                Err(Error::InconsistentProtocolFeatures(bits)) => {
                    assert_ne!(saved, 0);
                    assert_eq!(bits, saved);
                }
                Err(err) => panic!("Unexpected negotiation error: {err}"),
            }
            backend.join().unwrap();
        }
    }
}
