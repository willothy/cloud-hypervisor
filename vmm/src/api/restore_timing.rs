// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::MemoryRestoreMode;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Non-overlapping child spans of the device setup phase.
#[derive(Default)]
pub(crate) struct DeviceSetupTiming {
    pub(crate) disks: DiskConnectTiming,
    pub(crate) net: Duration,
    pub(crate) vsock: Duration,
    pub(crate) console: Duration,
    pub(crate) interrupt_controller: Duration,
}

impl DeviceSetupTiming {
    fn other(&self, total: Duration) -> Duration {
        total.saturating_sub(
            self.disks.ordinals.iter().sum::<Duration>()
                + self.disks.overflow
                + self.net
                + self.vsock
                + self.console
                + self.interrupt_controller,
        )
    }
}

/// The first eight vhost-user disk connects, in config order. Further
/// connects share one aggregate so the log line stays bounded.
#[derive(Default)]
pub(crate) struct DiskConnectTiming {
    ordinals: [Duration; 8],
    count: usize,
    overflow: Duration,
}

impl DiskConnectTiming {
    pub(crate) fn next(&mut self) -> &mut Duration {
        let ordinal = self.count;
        self.count += 1;
        self.ordinals.get_mut(ordinal).unwrap_or(&mut self.overflow)
    }

    fn overflow_count(&self) -> usize {
        self.count.saturating_sub(self.ordinals.len())
    }
}

impl fmt::Display for DiskConnectTiming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, elapsed) in self.ordinals[..self.count.min(self.ordinals.len())]
            .iter()
            .enumerate()
        {
            if i != 0 {
                f.write_str(",")?;
            }
            write!(f, "{}", elapsed.as_nanos())?;
        }
        f.write_str("]")
    }
}

/// Wall time on the VMM thread for a successful `vm.restore` API dispatch.
/// Starts after the API request log and ends at the internal reply handoff,
/// before emitting the timing record. It does not time the HTTP/DBus reply.
///
/// The phases are disjoint. Memory/UFFD preparation is the constructor's
/// RAM and fault setup; late capture UFFD and dirty logging are part of
/// `Vm::restore` in state restore, alongside vCPU creation and saved clock
/// decode. Device-specific resume and guest clock application count as
/// resume only when the API request actually resumes the VM.
pub struct RestoreTiming {
    pub(crate) started: Instant,
    pub(crate) snapshot_and_cpuid: Duration,
    pub(crate) memory_uffd: Duration,
    pub(crate) devices: Duration,
    device_setup: DeviceSetupTiming,
    pub(crate) state_restore: Duration,
    pub(crate) resume: Duration,
}

impl RestoreTiming {
    /// Opt in for this process after installing the logger. This does not
    /// change the log level for any other record.
    pub fn enable() {
        ENABLED.store(true, Ordering::Relaxed);
    }

    pub(super) fn start() -> Option<Self> {
        ENABLED.load(Ordering::Relaxed).then(|| Self {
            started: Instant::now(),
            snapshot_and_cpuid: Duration::ZERO,
            memory_uffd: Duration::ZERO,
            devices: Duration::ZERO,
            device_setup: DeviceSetupTiming::default(),
            state_restore: Duration::ZERO,
            resume: Duration::ZERO,
        })
    }

    /// Start a device setup interval and lend its nested timing accumulator
    /// separately from its outer elapsed counter.
    pub(crate) fn devices_phase(
        timing: Option<&mut Self>,
    ) -> (impl FnOnce() + '_, Option<&mut DeviceSetupTiming>) {
        let (total, setup) = timing
            .map(|t| (Some(&mut t.devices), Some(&mut t.device_setup)))
            .unwrap_or_default();
        (Self::phase(total), setup)
    }

    /// Add a disjoint interval on success, without reading the clock when
    /// disabled or sampling an unfinished phase on an early return.
    pub(crate) fn phase(elapsed: Option<&mut Duration>) -> impl FnOnce() + '_ {
        let started = elapsed.map(|elapsed| (elapsed, Instant::now()));
        move || {
            if let Some((elapsed, started)) = started {
                *elapsed += started.elapsed();
            }
        }
    }

    /// Work not bracketed by a named phase, including the reply handoff.
    fn other(&self, total: Duration) -> Duration {
        total.saturating_sub(
            self.snapshot_and_cpuid
                + self.memory_uffd
                + self.devices
                + self.state_restore
                + self.resume,
        )
    }

    /// Use the installed logger without applying the ordinary verbosity
    /// threshold to this explicitly enabled record.
    pub(super) fn log(self, memory_mode: MemoryRestoreMode, resumed: bool) {
        let total = self.started.elapsed();
        log::logger().log(
            &log::Record::builder()
                .level(log::Level::Info)
                .target(module_path!())
                .module_path(Some(module_path!()))
                .file(Some(file!()))
                .line(Some(line!()))
                .args(format_args!(
                    "vm_restore_timing requested_memory_mode={memory_mode:?} resumed={resumed} total_ns={} snapshot_and_cpuid_ns={} memory_uffd_ns={} devices_ns={} state_restore_ns={} resume_ns={} other_ns={} devices_vhost_user_blk_connect_ns={} devices_vhost_user_blk_connect_overflow_count={} devices_vhost_user_blk_connect_overflow_ns={} devices_net_ns={} devices_vsock_ns={} devices_console_ns={} devices_interrupt_controller_ns={} devices_other_ns={}",
                    total.as_nanos(),
                    self.snapshot_and_cpuid.as_nanos(),
                    self.memory_uffd.as_nanos(),
                    self.devices.as_nanos(),
                    self.state_restore.as_nanos(),
                    self.resume.as_nanos(),
                    self.other(total).as_nanos(),
                    self.device_setup.disks,
                    self.device_setup.disks.overflow_count(),
                    self.device_setup.disks.overflow.as_nanos(),
                    self.device_setup.net.as_nanos(),
                    self.device_setup.vsock.as_nanos(),
                    self.device_setup.console.as_nanos(),
                    self.device_setup.interrupt_controller.as_nanos(),
                    self.device_setup.other(self.devices).as_nanos(),
                ))
                .build(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_timing_accounts_for_the_unmeasured_intervals() {
        for resume in [Duration::ZERO, Duration::from_nanos(19)] {
            let timing = RestoreTiming {
                started: Instant::now(),
                snapshot_and_cpuid: Duration::from_nanos(3),
                memory_uffd: Duration::from_nanos(5),
                devices: Duration::from_nanos(7),
                device_setup: DeviceSetupTiming::default(),
                state_restore: Duration::from_nanos(11),
                resume,
            };
            let total = Duration::from_nanos(39) + resume;
            assert_eq!(timing.other(total), Duration::from_nanos(13));
        }
    }

    #[test]
    fn device_accounting_keeps_eight_disk_ordinals_and_sums_overflow() {
        let mut setup = DeviceSetupTiming {
            net: Duration::from_nanos(1),
            vsock: Duration::from_nanos(2),
            console: Duration::from_nanos(3),
            interrupt_controller: Duration::from_nanos(4),
            ..Default::default()
        };
        assert_eq!(setup.disks.to_string(), "[]");
        for ns in 1..=10 {
            *setup.disks.next() += Duration::from_nanos(ns);
        }
        assert_eq!(setup.disks.to_string(), "[1,2,3,4,5,6,7,8]");
        assert_eq!(setup.disks.overflow_count(), 2);
        assert_eq!(setup.disks.overflow, Duration::from_nanos(19));
        assert_eq!(
            setup.other(Duration::from_nanos(70)),
            Duration::from_nanos(5)
        );
    }
}
