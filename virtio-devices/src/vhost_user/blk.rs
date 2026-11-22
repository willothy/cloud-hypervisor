// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::offset_of;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::{io, result};

use anyhow::anyhow;
use block::VirtioBlockConfig;
use log::{error, info};
use seccompiler::SeccompAction;
use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_GEOMETRY, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
};
use vm_memory::ByteValued;
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use super::super::{ActivateResult, VirtioCommon, VirtioDevice, VirtioDeviceType};
use super::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use super::{DEFAULT_VIRTIO_FEATURES, Error, Result};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::vhost_user::{VhostUserCommon, VhostUserState};
use crate::{GuestRegionMmap, VIRTIO_F_ACCESS_PLATFORM, VirtioInterrupt, VirtioInterruptType};

const DEFAULT_QUEUE_NUMBER: usize = 1;

pub type State = VhostUserState<VirtioBlockConfig>;

fn get_block_config(vu: &mut VhostUserHandle, num_queues: usize) -> Result<VirtioBlockConfig> {
    let config_len = size_of::<VirtioBlockConfig>();
    let config_space = vec![0u8; config_len];
    let (_, config_space) = vu
        .socket_handle()
        .get_config(
            0,
            config_len as u32,
            VhostUserConfigFlags::WRITABLE,
            config_space.as_slice(),
        )
        .map_err(Error::VhostUserGetConfig)?;
    let mut config = VirtioBlockConfig::default();
    if let Some(backend_config) = VirtioBlockConfig::from_slice(config_space.as_slice()) {
        config = *backend_config;
        config.num_queues = num_queues as u16;
    }

    Ok(config)
}

/// Refuse to restore device `id` on a backend that doesn't offer every
/// virtio feature the snapshot's guest acked. `SET_FEATURES` only sends the
/// features both sides support, so a feature missing from the backend
/// would otherwise be dropped while the restored guest goes on using it.
/// `VIRTIO_F_ACCESS_PLATFORM` is the frontend's to offer, never the
/// backend's, so it is not required of it.
fn check_restored_features(id: &str, acked_features: u64, backend_features: u64) -> Result<()> {
    let missing = acked_features & !(1u64 << VIRTIO_F_ACCESS_PLATFORM) & !backend_features;
    if missing != 0 {
        return Err(Error::RestoredFeaturesUnsupported {
            id: id.to_owned(),
            missing,
        });
    }
    Ok(())
}

/// A restored device's config, reconciled with its new backend's.
struct RestoredConfig {
    config: VirtioBlockConfig,
    /// The capacity is the backend's and differs from the snapshot's, so the
    /// restored guest has to be told its config changed.
    capacity_changed: bool,
}

/// Reconcile the config the snapshot of device `id` saved with the one its
/// new backend reports.
///
/// A saved capacity of 0 is a placeholder: the device was captured with no
/// disk behind it, and the backend's capacity is taken. A nonzero saved
/// capacity is the disk the guest already sized itself to, and the backend
/// must report it unchanged. Every other field is read by the guest's driver
/// once, at probe, and never again, so it must match the snapshot's either
/// way. `writeback` is the exception: the driver sets it, so the snapshot's
/// value stands whatever the backend reports.
fn restored_config(
    id: &str,
    saved: VirtioBlockConfig,
    backend: VirtioBlockConfig,
) -> Result<RestoredConfig> {
    let unused1 = |config: &VirtioBlockConfig| {
        let [a, b, c] = config.unused1;
        u64::from(u32::from_le_bytes([a, b, c, 0]))
    };
    let fields = [
        (
            "size_max",
            u64::from(saved.size_max),
            u64::from(backend.size_max),
        ),
        (
            "seg_max",
            u64::from(saved.seg_max),
            u64::from(backend.seg_max),
        ),
        (
            "geometry.cylinders",
            u64::from(saved.geometry.cylinders),
            u64::from(backend.geometry.cylinders),
        ),
        (
            "geometry.heads",
            u64::from(saved.geometry.heads),
            u64::from(backend.geometry.heads),
        ),
        (
            "geometry.sectors",
            u64::from(saved.geometry.sectors),
            u64::from(backend.geometry.sectors),
        ),
        (
            "blk_size",
            u64::from(saved.blk_size),
            u64::from(backend.blk_size),
        ),
        (
            "physical_block_exp",
            u64::from(saved.physical_block_exp),
            u64::from(backend.physical_block_exp),
        ),
        (
            "alignment_offset",
            u64::from(saved.alignment_offset),
            u64::from(backend.alignment_offset),
        ),
        (
            "min_io_size",
            u64::from(saved.min_io_size),
            u64::from(backend.min_io_size),
        ),
        (
            "opt_io_size",
            u64::from(saved.opt_io_size),
            u64::from(backend.opt_io_size),
        ),
        ("unused", u64::from(saved.unused), u64::from(backend.unused)),
        (
            "num_queues",
            u64::from(saved.num_queues),
            u64::from(backend.num_queues),
        ),
        (
            "max_discard_sectors",
            u64::from(saved.max_discard_sectors),
            u64::from(backend.max_discard_sectors),
        ),
        (
            "max_discard_seg",
            u64::from(saved.max_discard_seg),
            u64::from(backend.max_discard_seg),
        ),
        (
            "discard_sector_alignment",
            u64::from(saved.discard_sector_alignment),
            u64::from(backend.discard_sector_alignment),
        ),
        (
            "max_write_zeroes_sectors",
            u64::from(saved.max_write_zeroes_sectors),
            u64::from(backend.max_write_zeroes_sectors),
        ),
        (
            "max_write_zeroes_seg",
            u64::from(saved.max_write_zeroes_seg),
            u64::from(backend.max_write_zeroes_seg),
        ),
        (
            "write_zeroes_may_unmap",
            u64::from(saved.write_zeroes_may_unmap),
            u64::from(backend.write_zeroes_may_unmap),
        ),
        ("unused1", unused1(&saved), unused1(&backend)),
    ];
    let saved_capacity = saved.capacity;
    let backend_capacity = backend.capacity;
    let capacity = (saved_capacity != 0).then_some(("capacity", saved_capacity, backend_capacity));
    if let Some((field, saved, backend)) = capacity
        .into_iter()
        .chain(fields)
        .find(|(_, saved, backend)| saved != backend)
    {
        return Err(Error::RestoredConfigMismatch {
            id: id.to_owned(),
            field,
            saved,
            backend,
        });
    }

    let mut config = saved;
    config.capacity = backend_capacity;
    Ok(RestoredConfig {
        config,
        capacity_changed: saved_capacity != backend_capacity,
    })
}

struct BackendReqHandler {
    vu: Arc<Mutex<VhostUserHandle>>,
    config: Arc<Mutex<VirtioBlockConfig>>,
    num_queues: usize,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
}

impl VhostUserFrontendReqHandler for BackendReqHandler {
    fn handle_config_change(&self) -> io::Result<u64> {
        let mut vu = self.vu.lock().unwrap();
        let config = get_block_config(&mut vu, self.num_queues).map_err(|e| {
            error!("Failed to refresh vhost-user-blk configuration: {e:?}");
            io::Error::other(e)
        })?;
        *self.config.lock().unwrap() = config;
        self.interrupt_cb
            .trigger(VirtioInterruptType::Config)
            .map_err(|e| {
                error!("Failed to signal vhost-user-blk config change: {e:?}");
                io::Error::other(e)
            })?;
        Ok(0)
    }
}

pub struct Blk {
    vu_common: VhostUserCommon,
    id: String,
    config: Arc<Mutex<VirtioBlockConfig>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    /// Restored with its backend's capacity in place of the snapshot's: the
    /// guest is sent a config-change interrupt when the device first
    /// resumes, so its driver reads the new capacity.
    config_changed_at_restore: bool,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(
        id: String,
        vu_cfg: VhostUserConfig,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
        faults: Option<super::BackendFaults>,
    ) -> Result<Blk> {
        let num_queues = vu_cfg.num_queues;

        // A restore is made against backends that are already serving, so it
        // connects once: a socket that is missing or refuses is a fault to
        // report, not one to wait out.
        let mut vu = if state.is_some() {
            VhostUserHandle::connect_vhost_user_once(
                &vu_cfg.socket,
                num_queues as u64,
                faults.as_ref(),
            )
            .map_err(|e| Error::RestoreConnect {
                id: id.clone(),
                socket: vu_cfg.socket.clone(),
                source: Box::new(e),
            })?
        } else {
            VhostUserHandle::connect_vhost_user(
                false,
                &vu_cfg.socket,
                num_queues as u64,
                false,
                &exit_evt,
                faults.as_ref(),
                |_| Ok(()),
            )?
        };

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            restored,
            paused,
            vring_bases,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-block {id}");

            check_restored_features(&id, state.acked_features, vu.backend_features())?;

            vu.set_protocol_features_vhost_user(
                state.acked_features,
                state.acked_protocol_features,
            )?;

            vu.restore_state(&state)?;

            let backend_config = get_block_config(&mut vu, num_queues)?;

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                restored_config(&id, state.config, backend_config)?,
                true,
                state.vring_bases,
            )
        } else {
            // Filling device and vring features VMM supports.
            let mut avail_features = (1 << VIRTIO_BLK_F_SIZE_MAX)
                | (1 << VIRTIO_BLK_F_SEG_MAX)
                | (1 << VIRTIO_BLK_F_GEOMETRY)
                | (1 << VIRTIO_BLK_F_RO)
                | (1 << VIRTIO_BLK_F_BLK_SIZE)
                | (1 << VIRTIO_BLK_F_FLUSH)
                | (1 << VIRTIO_BLK_F_TOPOLOGY)
                | (1 << VIRTIO_BLK_F_CONFIG_WCE)
                | (1 << VIRTIO_BLK_F_DISCARD)
                | (1 << VIRTIO_BLK_F_WRITE_ZEROES)
                | DEFAULT_VIRTIO_FEATURES;

            if num_queues > 1 {
                avail_features |= 1 << VIRTIO_BLK_F_MQ;
            }

            let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD
                | VhostUserProtocolFeatures::DEVICE_STATE
                | VhostUserProtocolFeatures::BACKEND_REQ;

            let (acked_features, acked_protocol_features) =
                vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

            let backend_num_queues =
                if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                    vu.socket_handle()
                        .get_queue_num()
                        .map_err(Error::VhostUserGetQueueMaxNum)? as usize
                } else {
                    DEFAULT_QUEUE_NUMBER
                };

            if num_queues > backend_num_queues {
                error!(
                    "vhost-user-blk requested too many queues ({num_queues}) since the backend only supports {backend_num_queues}\n"
                );
                return Err(Error::BadQueueNum);
            }

            let config = get_block_config(&mut vu, num_queues)?;

            let mut avail_features = acked_features;
            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }

            (
                avail_features,
                // If part of the available features that have been acked,
                // the PROTOCOL_FEATURES bit must be already set through
                // the VIRTIO acked features as we know the guest would
                // never ack it, thus the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                num_queues,
                RestoredConfig {
                    config,
                    capacity_changed: false,
                },
                false,
                None,
            )
        };

        Ok(Blk {
            vu_common: VhostUserCommon {
                virtio_common: VirtioCommon {
                    device_type: VirtioDeviceType::Block as u32,
                    queue_sizes: vec![vu_cfg.queue_size; num_queues],
                    avail_features,
                    acked_features,
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    min_queues: DEFAULT_QUEUE_NUMBER as u16,
                    paused: Arc::new(AtomicBool::new(paused)),
                    ..Default::default()
                },
                vu: Some(Arc::new(Mutex::new(vu))),
                faults,
                acked_protocol_features,
                socket_path: vu_cfg.socket,
                vu_num_queues,
                vring_bases,
                ..Default::default()
            },
            id,
            config: Arc::new(Mutex::new(restored.config)),
            seccomp_action,
            exit_evt,
            config_changed_at_restore: restored.capacity_changed,
        })
    }

    fn state(&self) -> result::Result<State, MigratableError> {
        self.vu_common.state(*self.config.lock().unwrap())
    }
}

impl Drop for Blk {
    fn drop(&mut self) {
        self.vu_common.shutdown();
    }
}

impl VirtioDevice for Blk {
    fn device_type(&self) -> u32 {
        self.vu_common.virtio_common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.vu_common.virtio_common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.vu_common.virtio_common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.vu_common.virtio_common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.lock().unwrap().as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset = offset_of!(VirtioBlockConfig, writeback) as u64;
        if offset != writeback_offset || data.len() != size_of::<u8>() {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        if let Some(vu) = &self.vu_common.vu {
            let mut vu = vu.lock().unwrap();
            let result = vu
                .socket_handle()
                .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
                .map_err(Error::VhostUserSetConfig);
            self.config.lock().unwrap().writeback = data[0];

            if let Err(e) = result {
                error!(
                    "Failed setting vhost-user-blk configuration for socket {} at offset 0x{offset:x} with length {}: {e:?}",
                    self.vu_common.socket_path,
                    data.len()
                );
            }
        } else {
            self.config.lock().unwrap().writeback = data[0];
        }
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            queues,
            device_status,
        } = context;
        self.vu_common
            .virtio_common
            .activate(&queues, Arc::clone(&interrupt_cb))?;

        let backend_req_handler = if self.vu_common.acked_protocol_features
            & VhostUserProtocolFeatures::BACKEND_REQ.bits()
            != 0
        {
            let mut handler = FrontendReqHandler::new(Arc::new(BackendReqHandler {
                vu: Arc::clone(self.vu_common.vu.as_ref().unwrap()),
                config: Arc::clone(&self.config),
                num_queues: self.vu_common.virtio_common.queue_sizes.len(),
                interrupt_cb: Arc::clone(&interrupt_cb),
            }))
            .map_err(|e| {
                crate::ActivateError::VhostUserSetup(Error::FrontendReqHandlerCreation(e))
            })?;

            if self.vu_common.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits()
                != 0
            {
                handler.set_reply_ack_flag(true);
            }

            Some(handler)
        } else {
            None
        };

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds()?;

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            Arc::clone(&interrupt_cb),
            self.vu_common.virtio_common.acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = Arc::clone(&self.vu_common.virtio_common.paused);
        let paused_sync = self.vu_common.virtio_common.paused_sync.clone();

        self.vu_common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostBlock,
            &self.exit_evt,
            Arc::clone(&device_status),
            Arc::clone(&interrupt_cb),
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;

        Ok(())
    }

    fn reset(&mut self) {
        self.vu_common.reset(&self.id);
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(region)
    }
}

impl Pausable for Blk {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.vu_common.virtio_common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.virtio_common.resume()?;
        self.vu_common.resume()?;
        if self.config_changed_at_restore {
            self.vu_common
                .virtio_common
                .trigger_interrupt(VirtioInterruptType::Config)
                .map_err(|e| {
                    MigratableError::Resume(anyhow!(
                        "Failed to signal the config change of restored vhost-user-block {}: {e:?}",
                        self.id
                    ))
                })?;
            self.config_changed_at_restore = false;
        }
        Ok(())
    }
}

impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state()?)
    }
}
impl Transportable for Blk {}

impl Migratable for Blk {
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log()
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log()
    }

    fn notify_started_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.notify_started_migration()
    }

    fn notify_failed_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.notify_failed_migration()
    }

    fn notify_completed_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.notify_completed_migration()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    use virtio_bindings::virtio_blk::VIRTIO_BLK_F_DISCARD;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    /// Restore a device whose backend should be at `socket`, and check it
    /// fails at once, naming the device and the socket.
    fn assert_restore_fails_at_once(socket: &str) {
        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let started = Instant::now();
        let result = Blk::new(
            "base".to_owned(),
            VhostUserConfig {
                socket: socket.to_owned(),
                num_queues: 1,
                queue_size: 128,
            },
            SeccompAction::Allow,
            exit_evt,
            false,
            Some(State::default()),
            None,
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the restore waited {:?} for its backend",
            started.elapsed()
        );
        match result {
            Err(Error::RestoreConnect {
                id,
                socket: named,
                source,
            }) => {
                assert_eq!(id, "base");
                assert_eq!(named, socket);
                assert!(
                    matches!(*source, Error::VhostUserConnect(_)),
                    "expected a connect error, got {source:?}"
                );
            }
            Err(other) => panic!("expected RestoreConnect, got {other:?}"),
            Ok(_) => panic!("the restore connected to a backend that isn't serving"),
        }
    }

    #[test]
    fn a_restore_does_not_wait_for_a_missing_socket() {
        let dir = TempDir::new_with_prefix("/tmp/vhost-user-blk-restore-").unwrap();
        let socket = dir.as_path().join("backend.sock");
        assert_restore_fails_at_once(socket.to_str().unwrap());
    }

    #[test]
    fn a_restore_does_not_wait_for_a_refusing_socket() {
        let dir = TempDir::new_with_prefix("/tmp/vhost-user-blk-restore-").unwrap();
        let socket = dir.as_path().join("backend.sock");
        drop(UnixListener::bind(&socket).unwrap());
        assert_restore_fails_at_once(socket.to_str().unwrap());
    }

    #[test]
    fn restore_accepts_a_backend_offering_every_acked_feature() {
        let acked = (1u64 << VIRTIO_BLK_F_RO) | (1u64 << VIRTIO_BLK_F_FLUSH);
        let backend = acked | (1u64 << VIRTIO_BLK_F_DISCARD);
        check_restored_features("base", acked, backend).unwrap();
    }

    #[test]
    fn restore_names_the_acked_features_a_backend_lacks() {
        let acked = (1u64 << VIRTIO_BLK_F_RO) | (1u64 << VIRTIO_BLK_F_FLUSH);
        let backend = 1u64 << VIRTIO_BLK_F_FLUSH;
        match check_restored_features("base", acked, backend) {
            Err(Error::RestoredFeaturesUnsupported { id, missing }) => {
                assert_eq!(id, "base");
                assert_eq!(missing, 1u64 << VIRTIO_BLK_F_RO);
            }
            other => panic!("expected RestoredFeaturesUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn restore_does_not_require_access_platform_of_the_backend() {
        let acked = (1u64 << VIRTIO_BLK_F_FLUSH) | (1u64 << VIRTIO_F_ACCESS_PLATFORM);
        check_restored_features("base", acked, 1u64 << VIRTIO_BLK_F_FLUSH).unwrap();
    }

    /// A config as a backend reports it, with every field nonzero so a
    /// mismatch in any one of them is visible.
    fn backend_config(capacity: u64) -> VirtioBlockConfig {
        VirtioBlockConfig {
            capacity,
            size_max: 65535,
            seg_max: 126,
            geometry: block::VirtioBlockGeometry {
                cylinders: 16,
                heads: 4,
                sectors: 32,
            },
            blk_size: 512,
            physical_block_exp: 3,
            alignment_offset: 1,
            min_io_size: 8,
            opt_io_size: 64,
            writeback: 0,
            unused: 1,
            num_queues: 2,
            max_discard_sectors: 1 << 20,
            max_discard_seg: 1,
            discard_sector_alignment: 8,
            max_write_zeroes_sectors: 1 << 20,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            unused1: [1, 2, 3],
        }
    }

    /// A field a backend must report unchanged, with a change to it.
    type FieldChange = (&'static str, fn(&mut VirtioBlockConfig));

    /// Every field a backend must report unchanged.
    const FIELD_CHANGES: &[FieldChange] = &[
        ("size_max", |c| c.size_max += 1),
        ("seg_max", |c| c.seg_max += 1),
        ("geometry.cylinders", |c| c.geometry.cylinders += 1),
        ("geometry.heads", |c| c.geometry.heads += 1),
        ("geometry.sectors", |c| c.geometry.sectors += 1),
        ("blk_size", |c| c.blk_size *= 8),
        ("physical_block_exp", |c| c.physical_block_exp += 1),
        ("alignment_offset", |c| c.alignment_offset += 1),
        ("min_io_size", |c| c.min_io_size += 1),
        ("opt_io_size", |c| c.opt_io_size += 1),
        ("unused", |c| c.unused += 1),
        ("num_queues", |c| c.num_queues += 1),
        ("max_discard_sectors", |c| c.max_discard_sectors += 1),
        ("max_discard_seg", |c| c.max_discard_seg += 1),
        ("discard_sector_alignment", |c| {
            c.discard_sector_alignment += 1;
        }),
        ("max_write_zeroes_sectors", |c| {
            c.max_write_zeroes_sectors += 1;
        }),
        ("max_write_zeroes_seg", |c| c.max_write_zeroes_seg += 1),
        ("write_zeroes_may_unmap", |c| c.write_zeroes_may_unmap = 0),
        ("unused1", |c| c.unused1[2] += 1),
    ];

    fn assert_mismatch(
        result: Result<RestoredConfig>,
        want_field: &str,
        want_saved: u64,
        want_backend: u64,
    ) {
        match result {
            Err(Error::RestoredConfigMismatch {
                id,
                field,
                saved,
                backend,
            }) => {
                assert_eq!(id, "scratch");
                assert_eq!(field, want_field);
                assert_eq!(saved, want_saved);
                assert_eq!(backend, want_backend);
            }
            Err(other) => panic!("expected a mismatch on {want_field}, got {other:?}"),
            Ok(_) => panic!("expected a mismatch on {want_field}, got a restored config"),
        }
    }

    #[test]
    fn a_placeholder_takes_the_backends_capacity() {
        let mut saved = backend_config(0);
        saved.writeback = 1;
        let restored = restored_config("scratch", saved, backend_config(2048)).unwrap();
        assert!(restored.capacity_changed);
        assert_eq!({ restored.config.capacity }, 2048);
        assert_eq!({ restored.config.writeback }, 1);
        assert_eq!({ restored.config.seg_max }, 126);
    }

    #[test]
    fn a_placeholder_on_an_empty_backend_has_no_config_change() {
        let restored = restored_config("scratch", backend_config(0), backend_config(0)).unwrap();
        assert!(!restored.capacity_changed);
        assert_eq!({ restored.config.capacity }, 0);
    }

    #[test]
    fn a_checkpoint_restores_on_a_backend_reporting_its_config() {
        let mut saved = backend_config(2048);
        saved.writeback = 1;
        let restored = restored_config("scratch", saved, backend_config(2048)).unwrap();
        assert!(!restored.capacity_changed);
        assert_eq!({ restored.config.capacity }, 2048);
        assert_eq!({ restored.config.writeback }, 1);
    }

    #[test]
    fn a_checkpoint_refuses_a_backend_of_another_capacity() {
        assert_mismatch(
            restored_config("scratch", backend_config(2048), backend_config(4096)),
            "capacity",
            2048,
            4096,
        );
        assert_mismatch(
            restored_config("scratch", backend_config(2048), backend_config(0)),
            "capacity",
            2048,
            0,
        );
    }

    #[test]
    fn a_placeholder_refuses_a_backend_differing_in_any_other_field() {
        for (field, change) in FIELD_CHANGES {
            let mut backend = backend_config(2048);
            change(&mut backend);
            let result = restored_config("scratch", backend_config(0), backend);
            let (saved, theirs) = field_values(field, &backend_config(0), &backend);
            assert_mismatch(result, field, saved, theirs);
        }
    }

    #[test]
    fn a_checkpoint_refuses_a_backend_differing_in_any_other_field() {
        for (field, change) in FIELD_CHANGES {
            let mut backend = backend_config(2048);
            change(&mut backend);
            let result = restored_config("scratch", backend_config(2048), backend);
            let (saved, theirs) = field_values(field, &backend_config(2048), &backend);
            assert_mismatch(result, field, saved, theirs);
        }
    }

    #[test]
    fn the_backends_writeback_is_not_compared() {
        let mut backend = backend_config(2048);
        backend.writeback = 1;
        restored_config("scratch", backend_config(0), backend).unwrap();
        restored_config("scratch", backend_config(2048), backend).unwrap();
    }

    /// The values of `field` in `saved` and `backend`, as a mismatch on it
    /// names them.
    fn field_values(
        field: &str,
        saved: &VirtioBlockConfig,
        backend: &VirtioBlockConfig,
    ) -> (u64, u64) {
        let value = |c: &VirtioBlockConfig| -> u64 {
            match field {
                "size_max" => c.size_max.into(),
                "seg_max" => c.seg_max.into(),
                "geometry.cylinders" => c.geometry.cylinders.into(),
                "geometry.heads" => c.geometry.heads.into(),
                "geometry.sectors" => c.geometry.sectors.into(),
                "blk_size" => c.blk_size.into(),
                "physical_block_exp" => c.physical_block_exp.into(),
                "alignment_offset" => c.alignment_offset.into(),
                "min_io_size" => c.min_io_size.into(),
                "opt_io_size" => c.opt_io_size.into(),
                "unused" => c.unused.into(),
                "num_queues" => c.num_queues.into(),
                "max_discard_sectors" => c.max_discard_sectors.into(),
                "max_discard_seg" => c.max_discard_seg.into(),
                "discard_sector_alignment" => c.discard_sector_alignment.into(),
                "max_write_zeroes_sectors" => c.max_write_zeroes_sectors.into(),
                "max_write_zeroes_seg" => c.max_write_zeroes_seg.into(),
                "write_zeroes_may_unmap" => c.write_zeroes_may_unmap.into(),
                "unused1" => {
                    let [a, b, c] = c.unused1;
                    u32::from_le_bytes([a, b, c, 0]).into()
                }
                other => panic!("no field {other}"),
            }
        };
        (value(saved), value(backend))
    }
}
