// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_device::UserspaceMapping;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryLoadGuard,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vm_virtio::checked_descriptor::DescriptorChainExt;
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1,
    VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::{GuestMemoryMmap, VirtioInterrupt, VirtioInterruptType};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

/// Layout of the empty-placeholder record this VMM writes into a saved
/// [`PmemState`]. A restore refuses a placeholder recorded in any other.
const PMEM_PLACEHOLDER_LAYOUT: u32 = 1;

/// The required alignment of a pmem device's size and window.
const PMEM_ALIGNMENT: u64 = 0x20_0000;

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[repr(C)]
struct VirtioPmemConfig {
    start: u64,
    size: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemConfig {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioPmemReq {
    type_: u32,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemReq {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioPmemResp {
    ret: u32,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemResp {}

#[derive(Error, Debug)]
enum Error {
    #[error("Bad guest memory addresses")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Unexpected write-only descriptor")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Unexpected read-only descriptor")]
    UnexpectedReadOnlyDescriptor,
    #[error("Descriptor chain too short")]
    DescriptorChainTooShort,
    #[error("Buffer length too small")]
    BufferLengthTooSmall,
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
}

#[derive(Debug, PartialEq, Eq)]
enum RequestType {
    Flush,
    Unknown(u32),
}

struct Request {
    type_: RequestType,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> result::Result<Request, Error> {
        let desc = desc_chain
            .next_checked(access_platform)
            .map_err(|addr| Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr)))?
            .ok_or(Error::DescriptorChainTooShort)?;
        // The descriptor contains the request type which MUST be readable.
        if desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        if (desc.len() as usize) < size_of::<VirtioPmemReq>() {
            return Err(Error::InvalidRequest);
        }

        let request: VirtioPmemReq = desc_chain
            .memory()
            .read_obj(desc.addr())
            .map_err(Error::GuestMemory)?;

        let request_type = match request.type_ {
            VIRTIO_PMEM_REQ_TYPE_FLUSH => RequestType::Flush,
            t => RequestType::Unknown(t),
        };

        let status_desc = desc_chain
            .next_checked(access_platform)
            .map_err(|addr| Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr)))?
            .ok_or(Error::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if (status_desc.len() as usize) < size_of::<VirtioPmemResp>() {
            return Err(Error::BufferLengthTooSmall);
        }

        Ok(Request {
            type_: request_type,
            status_addr: status_desc.addr(),
        })
    }
}

struct PmemEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queue: Queue,
    disk: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl PmemEpollHandler {
    fn process_queue(&mut self) -> result::Result<bool, Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) = self.queue.pop_descriptor_chain(self.mem.memory()) {
            let len = match Request::parse(&mut desc_chain, self.access_platform.as_deref()) {
                Ok(ref req) => {
                    let status_code = match req.type_ {
                        RequestType::Flush => match self.disk.sync_all() {
                            Ok(()) => VIRTIO_PMEM_RESP_TYPE_OK,
                            Err(e) => {
                                error!("Failed flushing disk image: {e}");
                                VIRTIO_PMEM_RESP_TYPE_EIO
                            }
                        },
                        RequestType::Unknown(t) => {
                            warn!("Unknown request type: {t}");
                            VIRTIO_PMEM_RESP_TYPE_EIO
                        }
                    };

                    let resp = VirtioPmemResp { ret: status_code };
                    match desc_chain.memory().write_obj(resp, req.status_addr) {
                        Ok(_) => size_of::<VirtioPmemResp>() as u32,
                        Err(e) => {
                            error!("bad guest memory address: {e}");
                            0
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {e:?}");
                    0
                }
            };

            self.queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
        }

        Ok(used_descs)
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(0))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for PmemEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                let needs_notification = self.process_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to process queue : {e:?}"))
                })?;

                if needs_notification {
                    self.signal_used_queue().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
                    })?;
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

/// The backing of a pmem device: the file and its mapping into the guest.
pub struct PmemBacking {
    pub disk: File,
    pub mapping: UserspaceMapping,
}

pub struct Pmem {
    common: VirtioCommon,
    id: String,
    disk: Option<File>,
    config: VirtioPmemConfig,
    mapping: Option<UserspaceMapping>,
    placeholder: Option<PmemPlaceholder>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

/// The mark a saved empty placeholder carries, so that a saved size of 0
/// is never mistaken for a placeholder by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PmemPlaceholder {
    layout: u32,
}

#[derive(Serialize, Deserialize)]
pub struct PmemState {
    avail_features: u64,
    acked_features: u64,
    config: VirtioPmemConfig,
    /// Set when the device was saved as an empty placeholder: a reserved
    /// window with no backing, reported to the guest with size 0.
    #[serde(default)]
    placeholder: Option<PmemPlaceholder>,
}

/// Why a saved pmem device's state can't be restored.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PmemStateError {
    /// The saved size is 0 but the device isn't marked as a placeholder.
    #[error("Saved virtio-pmem device has size 0 but is not marked as an empty placeholder")]
    UnmarkedEmpty,
    /// The placeholder mark is in a layout this VMM doesn't know.
    #[error("Saved virtio-pmem placeholder uses unknown layout {0}")]
    UnknownPlaceholderLayout(u32),
    /// The device is marked as a placeholder but has a size.
    #[error("Saved virtio-pmem placeholder has non-zero size {0:#x}")]
    PlaceholderWithSize(u64),
}

/// What a saved pmem device showed the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmemSavedGeometry {
    /// An empty placeholder whose window starts at `start`; the guest saw
    /// size 0.
    Placeholder { start: u64 },
    /// A backed device the guest saw at `start`, `size` bytes long.
    Backed { start: u64, size: u64 },
}

/// Why a backing can't be given to a restored pmem device.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PmemBindError {
    /// The saved device's start is not the base of its saved window.
    #[error("Saved virtio-pmem start {start:#x} is not its window base {window_base:#x}")]
    StartNotWindowBase { start: u64, window_base: u64 },
    /// A placeholder was given an empty backing.
    #[error("Backing for the virtio-pmem placeholder is empty")]
    EmptyBacking,
    /// A placeholder was given a backing whose size is not 2 MiB aligned.
    #[error("Backing size {0:#x} for the virtio-pmem placeholder is not 2 MiB aligned")]
    BackingNotAligned(u64),
    /// A placeholder was given a backing larger than its window.
    #[error("Backing size {size:#x} does not fit the virtio-pmem window of {window:#x}")]
    BackingExceedsWindow { size: u64, window: u64 },
    /// A device the guest already saw was given a backing of another size.
    #[error("Backing size {backing:#x} differs from the saved virtio-pmem size {saved:#x}")]
    SizeMismatch { saved: u64, backing: u64 },
}

impl PmemState {
    /// What the saved device showed the guest, refusing a state that
    /// records size 0 without the placeholder mark, or a mark this VMM
    /// doesn't know.
    pub fn geometry(&self) -> result::Result<PmemSavedGeometry, PmemStateError> {
        let start = u64::from_le(self.config.start);
        let size = u64::from_le(self.config.size);
        match self.placeholder {
            Some(PmemPlaceholder { layout }) if layout != PMEM_PLACEHOLDER_LAYOUT => {
                Err(PmemStateError::UnknownPlaceholderLayout(layout))
            }
            Some(_) if size != 0 => Err(PmemStateError::PlaceholderWithSize(size)),
            Some(_) => Ok(PmemSavedGeometry::Placeholder { start }),
            None if size == 0 => Err(PmemStateError::UnmarkedEmpty),
            None => Ok(PmemSavedGeometry::Backed { start, size }),
        }
    }
}

impl PmemSavedGeometry {
    /// The size to map for a backing of `backing_size` bytes given to the
    /// saved device, whose window is `window_size` bytes at `window_base`.
    ///
    /// A placeholder takes the backing's size, which must be non-zero, 2 MiB
    /// aligned and fit the window. A device the guest already saw keeps its
    /// saved size exactly, so the backing must be that size; its window is
    /// never consulted.
    pub fn bind(
        self,
        window_base: u64,
        window_size: u64,
        backing_size: u64,
    ) -> result::Result<u64, PmemBindError> {
        let start = match self {
            PmemSavedGeometry::Placeholder { start } | PmemSavedGeometry::Backed { start, .. } => {
                start
            }
        };
        if start != window_base {
            return Err(PmemBindError::StartNotWindowBase { start, window_base });
        }
        match self {
            PmemSavedGeometry::Placeholder { .. } => {
                if backing_size == 0 {
                    return Err(PmemBindError::EmptyBacking);
                }
                if !backing_size.is_multiple_of(PMEM_ALIGNMENT) {
                    return Err(PmemBindError::BackingNotAligned(backing_size));
                }
                if backing_size > window_size {
                    return Err(PmemBindError::BackingExceedsWindow {
                        size: backing_size,
                        window: window_size,
                    });
                }
                Ok(backing_size)
            }
            PmemSavedGeometry::Backed { size, .. } => {
                if backing_size != size {
                    return Err(PmemBindError::SizeMismatch {
                        saved: size,
                        backing: backing_size,
                    });
                }
                Ok(size)
            }
        }
    }
}

impl Pmem {
    /// Creates a virtio-pmem device whose window starts at `addr`.
    ///
    /// Without a `backing` the device is an empty placeholder: the guest
    /// sees it with size 0, it has no mapping, and its saved state is marked
    /// as a placeholder. Restoring a saved placeholder with a backing binds
    /// it, so the guest sees the backing's mapping size from then on.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        backing: Option<PmemBacking>,
        addr: GuestAddress,
        access_platform_enabled: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<PmemState>,
    ) -> io::Result<Pmem> {
        let mapping_size = backing
            .as_ref()
            .map(|backing| backing.mapping.mapping.size() as u64);
        let (avail_features, acked_features, config, placeholder, paused) = if let Some(state) =
            state
        {
            info!("Restoring virtio-pmem {id}");
            let mut config = state.config;
            let mut placeholder = state.placeholder;
            match (placeholder, mapping_size) {
                (Some(_), Some(size)) => {
                    info!("Binding virtio-pmem placeholder {id} to a backing of {size:#x} bytes");
                    config.size = size.to_le();
                    placeholder = None;
                }
                (Some(_), None) => {}
                (None, Some(size)) if size == u64::from_le(config.size) => {}
                (None, mapping_size) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "saved virtio-pmem {id} has size {:#x} but its backing maps {mapping_size:#x?}",
                            u64::from_le(config.size)
                        ),
                    ));
                }
            }
            (
                state.avail_features,
                state.acked_features,
                config,
                placeholder,
                true,
            )
        } else {
            let config = VirtioPmemConfig {
                start: addr.raw_value().to_le(),
                size: mapping_size.unwrap_or(0).to_le(),
            };
            let placeholder = backing.is_none().then_some(PmemPlaceholder {
                layout: PMEM_PLACEHOLDER_LAYOUT,
            });

            let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }
            (avail_features, 0, config, placeholder, false)
        };
        let (disk, mapping) = match backing {
            Some(PmemBacking { disk, mapping }) => (Some(disk), Some(mapping)),
            None => (None, None),
        };

        Ok(Pmem {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Pmem as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                acked_features,
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            disk,
            config,
            mapping,
            placeholder,
            seccomp_action,
            exit_evt,
        })
    }

    fn state(&self) -> PmemState {
        PmemState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            placeholder: self.placeholder,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl VirtioDevice for Pmem {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.common.activate(&queues, Arc::clone(&interrupt_cb))?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds()?;
        if let Some(disk) = self.disk.as_ref() {
            let disk = disk.try_clone().map_err(|e| {
                error!("failed cloning pmem disk: {e}");
                ActivateError::BadActivate
            })?;

            let (_, queue, queue_evt) = queues.remove(0);

            let mut handler = PmemEpollHandler {
                mem,
                queue,
                disk,
                interrupt_cb: Arc::clone(&interrupt_cb),
                queue_evt,
                kill_evt,
                pause_evt,
                access_platform: self.common.access_platform(),
            };

            let paused = Arc::clone(&self.common.paused);
            let paused_sync = self.common.paused_sync.clone();

            self.common.spawn_worker(
                &self.id,
                &self.seccomp_action,
                Thread::VirtioPmem,
                &self.exit_evt,
                Arc::clone(&device_status),
                Arc::clone(&interrupt_cb),
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;

            event!("virtio-device", "activated", "id", &self.id);
            return Ok(());
        }
        error!(
            "virtio-pmem {} is an empty placeholder with no backing to serve",
            self.id
        );
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) {
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        self.mapping.iter().cloned().collect()
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }
}

impl Pausable for Pmem {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Pmem {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for Pmem {}
impl Migratable for Pmem {}

#[cfg(test)]
mod tests {
    use vm_memory::MmapRegion;
    use vm_memory::bitmap::AtomicBitmap;
    use vmm_sys_util::eventfd::EFD_NONBLOCK;

    use super::*;

    const WINDOW_BASE: u64 = 0x1_0000_0000;
    const MIB2: u64 = 0x20_0000;

    fn backing(size: u64) -> PmemBacking {
        PmemBacking {
            disk: File::open("/dev/null").unwrap(),
            mapping: UserspaceMapping {
                mem_slot: 0,
                addr: GuestAddress(WINDOW_BASE),
                mapping: Arc::new(MmapRegion::<AtomicBitmap>::new(size as usize).unwrap()),
                mergeable: false,
            },
        }
    }

    fn pmem(backing: Option<PmemBacking>, state: Option<PmemState>) -> io::Result<Pmem> {
        Pmem::new(
            "pmem0".to_owned(),
            backing,
            GuestAddress(WINDOW_BASE),
            false,
            SeccompAction::Allow,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            state,
        )
    }

    fn guest_config(pmem: &Pmem) -> (u64, u64) {
        let mut data = [0u8; 16];
        pmem.read_config(0, &mut data);
        (
            u64::from_le_bytes(data[..8].try_into().unwrap()),
            u64::from_le_bytes(data[8..].try_into().unwrap()),
        )
    }

    /// The state the device's snapshot carries, read back from it.
    fn saved(pmem: &mut Pmem) -> PmemState {
        pmem.snapshot().unwrap().to_state().unwrap()
    }

    #[test]
    fn test_placeholder_has_no_mapping_and_reports_size_zero() {
        let mut placeholder = pmem(None, None).unwrap();
        assert_eq!(guest_config(&placeholder), (WINDOW_BASE, 0));
        assert!(placeholder.userspace_mappings().is_empty());
        assert_eq!(
            saved(&mut placeholder).geometry(),
            Ok(PmemSavedGeometry::Placeholder { start: WINDOW_BASE })
        );
    }

    #[test]
    fn test_restored_placeholder_stays_empty_without_a_backing() {
        let state = saved(&mut pmem(None, None).unwrap());
        let mut restored = pmem(None, Some(state)).unwrap();
        assert_eq!(guest_config(&restored), (WINDOW_BASE, 0));
        assert!(restored.userspace_mappings().is_empty());
        assert_eq!(
            saved(&mut restored).geometry(),
            Ok(PmemSavedGeometry::Placeholder { start: WINDOW_BASE })
        );
    }

    #[test]
    fn test_restored_placeholder_takes_the_backing_size() {
        let state = saved(&mut pmem(None, None).unwrap());
        let mut restored = pmem(Some(backing(2 * MIB2)), Some(state)).unwrap();
        assert_eq!(guest_config(&restored), (WINDOW_BASE, 2 * MIB2));
        assert_eq!(restored.userspace_mappings().len(), 1);
        assert_eq!(
            saved(&mut restored).geometry(),
            Ok(PmemSavedGeometry::Backed {
                start: WINDOW_BASE,
                size: 2 * MIB2
            })
        );
    }

    #[test]
    fn test_restored_backed_device_keeps_its_geometry() {
        let state = saved(&mut pmem(Some(backing(MIB2)), None).unwrap());
        let restored = pmem(Some(backing(MIB2)), Some(state)).unwrap();
        assert_eq!(guest_config(&restored), (WINDOW_BASE, MIB2));

        // A backed device can't be restored with a mapping of another size,
        // nor without one.
        let state = saved(&mut pmem(Some(backing(MIB2)), None).unwrap());
        assert!(pmem(Some(backing(2 * MIB2)), Some(state)).is_err());
        let state = saved(&mut pmem(Some(backing(MIB2)), None).unwrap());
        assert!(pmem(None, Some(state)).is_err());
    }

    #[test]
    fn test_saved_state_geometry_refusals() {
        let state = |size: u64, placeholder: Option<u32>| PmemState {
            avail_features: 0,
            acked_features: 0,
            config: VirtioPmemConfig {
                start: WINDOW_BASE.to_le(),
                size: size.to_le(),
            },
            placeholder: placeholder.map(|layout| PmemPlaceholder { layout }),
        };
        assert_eq!(
            state(0, None).geometry(),
            Err(PmemStateError::UnmarkedEmpty)
        );
        assert_eq!(
            state(0, Some(2)).geometry(),
            Err(PmemStateError::UnknownPlaceholderLayout(2))
        );
        assert_eq!(
            state(MIB2, Some(PMEM_PLACEHOLDER_LAYOUT)).geometry(),
            Err(PmemStateError::PlaceholderWithSize(MIB2))
        );

        // A state saved before placeholders existed has no mark and is a
        // backed device.
        #[derive(Serialize)]
        struct OldPmemState {
            avail_features: u64,
            acked_features: u64,
            config: VirtioPmemConfig,
        }
        let old: PmemState = Snapshot::new_from_state(&OldPmemState {
            avail_features: 0,
            acked_features: 0,
            config: VirtioPmemConfig {
                start: WINDOW_BASE.to_le(),
                size: MIB2.to_le(),
            },
        })
        .unwrap()
        .to_state()
        .unwrap();
        assert_eq!(
            old.geometry(),
            Ok(PmemSavedGeometry::Backed {
                start: WINDOW_BASE,
                size: MIB2
            })
        );
    }

    #[test]
    fn test_bind_placeholder() {
        let placeholder = PmemSavedGeometry::Placeholder { start: WINDOW_BASE };
        let window = 4 * MIB2;
        assert_eq!(placeholder.bind(WINDOW_BASE, window, MIB2), Ok(MIB2));
        assert_eq!(placeholder.bind(WINDOW_BASE, window, window), Ok(window));
        assert_eq!(
            placeholder.bind(WINDOW_BASE, window, 0),
            Err(PmemBindError::EmptyBacking)
        );
        assert_eq!(
            placeholder.bind(WINDOW_BASE, window, MIB2 + 4096),
            Err(PmemBindError::BackingNotAligned(MIB2 + 4096))
        );
        assert_eq!(
            placeholder.bind(WINDOW_BASE, window, window + MIB2),
            Err(PmemBindError::BackingExceedsWindow {
                size: window + MIB2,
                window
            })
        );
        assert_eq!(
            placeholder.bind(WINDOW_BASE + MIB2, window, MIB2),
            Err(PmemBindError::StartNotWindowBase {
                start: WINDOW_BASE,
                window_base: WINDOW_BASE + MIB2
            })
        );
    }

    #[test]
    fn test_bind_backed_requires_the_saved_size() {
        let backed = PmemSavedGeometry::Backed {
            start: WINDOW_BASE,
            size: 3 * MIB2,
        };
        assert_eq!(backed.bind(WINDOW_BASE, 3 * MIB2, 3 * MIB2), Ok(3 * MIB2));
        assert_eq!(
            backed.bind(WINDOW_BASE, 3 * MIB2, 2 * MIB2),
            Err(PmemBindError::SizeMismatch {
                saved: 3 * MIB2,
                backing: 2 * MIB2
            })
        );
        // The window bound is never applied to a device the guest saw.
        assert_eq!(backed.bind(WINDOW_BASE, MIB2, 3 * MIB2), Ok(3 * MIB2));
        assert_eq!(
            backed.bind(WINDOW_BASE + MIB2, 3 * MIB2, 3 * MIB2),
            Err(PmemBindError::StartNotWindowBase {
                start: WINDOW_BASE,
                window_base: WINDOW_BASE + MIB2
            })
        );
    }
}
