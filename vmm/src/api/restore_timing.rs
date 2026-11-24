// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::MemoryRestoreMode;

static ENABLED: AtomicBool = AtomicBool::new(false);

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
            state_restore: Duration::ZERO,
            resume: Duration::ZERO,
        })
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
                    "vm_restore_timing requested_memory_mode={memory_mode:?} resumed={resumed} total_ns={} snapshot_and_cpuid_ns={} memory_uffd_ns={} devices_ns={} state_restore_ns={} resume_ns={} other_ns={}",
                    total.as_nanos(),
                    self.snapshot_and_cpuid.as_nanos(),
                    self.memory_uffd.as_nanos(),
                    self.devices.as_nanos(),
                    self.state_restore.as_nanos(),
                    self.resume.as_nanos(),
                    self.other(total).as_nanos(),
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
                state_restore: Duration::from_nanos(11),
                resume,
            };
            let total = Duration::from_nanos(39) + resume;
            assert_eq!(timing.other(total), Duration::from_nanos(13));
        }
    }
}
