// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Why a `vm.restore` failed, classified at the failing site.
//!
//! Every failure of a restore is a [`RestoreFailure`]: the [`RestoreSite`]
//! that failed, the errno and KVM ioctl when the site is a system call or
//! an ioctl, and the [`RestoreKind`] the site's rule gives them. The kind
//! tells the VMM's manager whose fault the failure is: the snapshot's, the
//! node's, the host's for lacking what the snapshot needs, the request's,
//! or nobody's it can name.
//!
//! [`RestoreFailure::of_vm_error`] classifies every [`VmError`] with
//! exhaustive matches over the error types a restore produces, so an error
//! variant added to any of them doesn't compile until it has a site.

use std::collections::HashMap;
use std::error::Error;
use std::{fmt, io};

#[cfg(target_arch = "x86_64")]
use hypervisor::arch::x86::MsrValueCheck;
use hypervisor::{HypervisorCpuError, HypervisorError, HypervisorVmError, KvmIoctl};
#[cfg(target_arch = "x86_64")]
use hypervisor::{IncompatibleVcpuState, MsrRefusal};
use virtio_devices::vhost_user;
use vm_migration::{MigratableError, UffdError};
use vmm_sys_util::errno;

use crate::console_devices::ConsoleDeviceError;
use crate::cpu::Error as CpuError;
use crate::device_manager::DeviceManagerError;
use crate::landlock::LandlockError;
use crate::memory_manager::Error as MemoryManagerError;
use crate::migration::{RecvError, SNAPSHOT_CONFIG_FILE};
use crate::vm::Error as VmError;

/// Whose fault a restore's failure is, decided at the failing site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreKind {
    /// The failure follows from the snapshot's bytes alone: they don't
    /// decode, or the kernel refuses a value they hold after every check
    /// of the host's capabilities passed.
    Snapshot,
    /// The failure follows from this node's resources or its own files:
    /// memory, descriptors, threads or space ran out, or a local file
    /// couldn't be opened or read.
    Node,
    /// The host can't present what the snapshot needs, decided by
    /// comparing the snapshot with what the host reports it supports.
    Incompatible,
    /// The VMM can't honestly tell the snapshot's fault from the host's,
    /// or the failure is one the restore isn't built to produce.
    Ambiguous,
    /// The request is invalid, or the VMM failed on input that came from
    /// the request rather than the snapshot.
    Request,
}

impl RestoreKind {
    /// The kind's name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            RestoreKind::Snapshot => "snapshot",
            RestoreKind::Node => "node",
            RestoreKind::Incompatible => "incompatible",
            RestoreKind::Ambiguous => "ambiguous",
            RestoreKind::Request => "request",
        }
    }
}

impl fmt::Display for RestoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a failing site knows beyond which site it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Evidence {
    /// A system call or ioctl failed with this errno.
    Errno(i32),
    /// A comparison with the host's capabilities found one missing.
    HostLacks,
    /// The kernel refused a value without an errno to say why.
    Refused,
    /// Nothing beyond the site.
    None,
}

macro_rules! restore_sites {
    ($($(#[$doc:meta])* $variant:ident => $name:literal,)*) => {
        /// Where a restore failed. Each site's name is part of the
        /// `vm.restore` API, and is never reused for another site.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum RestoreSite {
            $($(#[$doc])* $variant,)*
        }

        impl RestoreSite {
            /// Every site.
            pub const ALL: &'static [RestoreSite] = &[$(RestoreSite::$variant,)*];

            /// The site's name on the wire.
            pub fn name(self) -> &'static str {
                match self {
                    $(RestoreSite::$variant => $name,)*
                }
            }
        }
    };
}

restore_sites! {
    /// The request body isn't a valid restore configuration.
    RequestBody => "request-body",
    /// The request's file descriptors don't match its configuration.
    RequestFds => "request-fds",
    /// The VMM already has a VM.
    VmExists => "vm-exists",
    /// The VMM is migrating a VM.
    VmMigrating => "vm-migrating",
    /// The snapshot's source URL isn't a snapshot directory.
    SourceUrl => "source-url",
    /// The request's memory zone updates don't apply.
    MemoryZoneUpdate => "memory-zone-update",
    /// Opening or reading the snapshot's config.json.
    ConfigRead => "config-read",
    /// Decoding the snapshot's config.json.
    ConfigDecode => "config-decode",
    /// Opening or reading the snapshot's state.json.
    StateRead => "state-read",
    /// Decoding the snapshot's state.json.
    StateDecode => "state-decode",
    /// The VM's section of the snapshot is missing or doesn't decode.
    VmSection => "vm-section",
    /// Enabling the AMX state components the snapshot's config asks for.
    Amx => "amx",
    /// Reading the host's supported CPUID (`KVM_GET_SUPPORTED_CPUID`).
    SupportedCpuid => "supported-cpuid",
    /// The snapshot's CPUID asks for a feature the host lacks.
    CpuidCompatibility => "cpuid-compatibility",
    /// Creating the VM's console and serial devices.
    ConsoleDevices => "console-devices",
    /// A console or serial socket path is already in use.
    ConsoleSocketInUse => "console-socket-in-use",
    /// Duplicating one of the VMM's event descriptors.
    EventFdClone => "eventfd-clone",
    /// The host lacks a KVM capability the VMM requires.
    KvmExtensions => "kvm-extensions",
    /// Creating the KVM VM (`KVM_CREATE_VM` and the capabilities it is
    /// created with).
    KvmCreateVm => "kvm-create-vm",
    /// `KVM_SET_IDENTITY_MAP_ADDR`.
    KvmIdentityMap => "kvm-identity-map",
    /// `KVM_SET_TSS_ADDR`.
    KvmTss => "kvm-tss",
    /// Enabling the split irqchip.
    KvmSplitIrqchip => "kvm-split-irqchip",
    /// Enabling the x2APIC API.
    KvmX2apic => "kvm-x2apic",
    /// Opening a payload file (kernel, initramfs, firmware or IGVM) the
    /// snapshot's config names.
    PayloadFile => "payload-file",
    /// The VM's configuration, or the restore configuration applied to
    /// it, is invalid.
    VmConfig => "vm-config",
    /// The VM's NUMA configuration is invalid.
    Numa => "numa",
    /// The memory configuration is invalid.
    MemoryConfig => "memory-config",
    /// The memory manager's section of the snapshot doesn't decode.
    MemoryManagerState => "memory-manager-state",
    /// Creating guest memory: memfds, their size and seals, mappings and
    /// NUMA policy.
    GuestMemory => "guest-memory",
    /// The snapshot's memory layout doesn't fit the configured memory.
    MemoryLayout => "memory-layout",
    /// A saved memory range isn't page-aligned.
    UffdRanges => "uffd-ranges",
    /// Creating a userfaultfd.
    UffdCreate => "uffd-create",
    /// A saved memory range lies outside guest memory.
    UffdGpa => "uffd-gpa",
    /// `UFFDIO_REGISTER`.
    UffdRegister => "uffd-register",
    /// The kernel lacks a userfaultfd ioctl the registration needs.
    UffdIoctls => "uffd-ioctls",
    /// Starting the in-process userfaultfd handler.
    UffdHandler => "uffd-handler",
    /// Guest memory isn't backed by a file a fault handler can map.
    HandoffNotFileBacked => "handoff-not-file-backed",
    /// Connecting to the fault handler's socket.
    PageServerConnect => "page-server-connect",
    /// Handing the userfaultfd to the fault handler, or settling with it.
    PageServerHandoff => "page-server-handoff",
    /// Opening, reading or mapping the snapshot's memory file.
    MemoryFile => "memory-file",
    /// Restoring memory in a way none of the sites above covers.
    MemoryRestore => "memory-restore",
    /// Setting up the vCPU manager.
    CpuManager => "cpu-manager",
    /// Creating a device.
    DeviceCreate => "device-create",
    /// Connecting to a restored vhost-user device's backend, which the
    /// VMM's manager brings up before the restore.
    VhostUserBackendConnect => "vhost-user-backend-connect",
    /// A restored vhost-user device's backend doesn't offer a feature the
    /// snapshot acked, or reports a config the snapshot's guest can't take.
    VhostUserBackendMismatch => "vhost-user-backend-mismatch",
    /// A device's configuration is invalid.
    DeviceConfig => "device-config",
    /// A device's section of the snapshot doesn't decode.
    DeviceState => "device-state",
    /// Creating the interrupt controller.
    InterruptController => "interrupt-controller",
    /// `KVM_SET_USER_MEMORY_REGION`.
    KvmMemorySlot => "kvm-memory-slot",
    /// Initializing the hypervisor VM.
    VmInit => "vm-init",
    /// Holding the guest clock of a snapshot that didn't pair it with the
    /// TSC.
    HeldClockUnpaired => "held-clock-unpaired",
    /// `KVM_CREATE_VCPU`.
    KvmCreateVcpu => "kvm-create-vcpu",
    /// A vCPU's section of the snapshot doesn't decode, or doesn't fit
    /// KVM's structures.
    VcpuStateDecode => "vcpu-state-decode",
    /// Reading what the host supports for checking a vCPU's state.
    VcpuHostCapabilities => "vcpu-host-capabilities",
    /// `KVM_SET_CPUID2`.
    KvmSetCpuid2 => "kvm-set-cpuid2",
    /// `KVM_SET_MP_STATE`.
    KvmSetMpState => "kvm-set-mp-state",
    /// `KVM_SET_REGS`.
    KvmSetRegs => "kvm-set-regs",
    /// `KVM_SET_SREGS`, and the check of CR4 against the host.
    KvmSetSregs => "kvm-set-sregs",
    /// `KVM_SET_XSAVE`, and the check of its components against the host.
    KvmSetXsave => "kvm-set-xsave",
    /// `KVM_SET_XCRS`, and the check of XCR0 against the host.
    KvmSetXcrs => "kvm-set-xcrs",
    /// `KVM_SET_LAPIC`.
    KvmSetLapic => "kvm-set-lapic",
    /// `KVM_SET_FPU`.
    KvmSetFpu => "kvm-set-fpu",
    /// `KVM_SET_TSC_KHZ`, and the check of the rate against the host.
    KvmSetTscKhz => "kvm-set-tsc-khz",
    /// Enabling the Hyper-V SynIC, and the check that the host has it.
    KvmEnableSynic => "kvm-enable-synic",
    /// `KVM_SET_MSRS`, and the classification of an MSR KVM refused.
    KvmSetMsrs => "kvm-set-msrs",
    /// `KVM_SET_NESTED_STATE`, and the check of its format against the
    /// host.
    KvmSetNestedState => "kvm-set-nested-state",
    /// Setting the CET shadow-stack pointer, and the check that the host
    /// supports shadow stacks.
    KvmSetGuestSsp => "kvm-set-guest-ssp",
    /// `KVM_SET_VCPU_EVENTS`, and the check of its flags against the VM.
    KvmSetVcpuEvents => "kvm-set-vcpu-events",
    /// Restoring a vCPU's state in a way none of the sites above covers.
    VcpuState => "vcpu-state",
    /// Applying Landlock.
    Landlock => "landlock",
    /// A Landlock rule names a path this host can't open.
    LandlockPath => "landlock-path",
    /// Locking the VM's disk images.
    DiskLock => "disk-lock",
    /// Starting dirty-page logging of guest memory or a device.
    DirtyLogStart => "dirty-log-start",
    /// Regenerating the VM generation ID.
    Vmgenid => "vmgenid",
    /// Starting the vCPU threads.
    VcpuThreads => "vcpu-threads",
    /// Resuming the restored VM.
    Resume => "resume",
    /// A failure the restore path isn't built to produce.
    Unexpected => "unexpected",
}

/// The errnos that mean this node ran out of a resource: memory, open
/// file descriptors, threads or retries, or space.
const RESOURCE_ERRNOS: [i32; 5] = [
    libc::ENOMEM,
    libc::EMFILE,
    libc::ENFILE,
    libc::EAGAIN,
    libc::ENOSPC,
];

impl RestoreSite {
    /// The kind of a failure at this site with `evidence`.
    pub fn classify(self, evidence: Evidence) -> RestoreKind {
        use Evidence::{Errno, HostLacks, Refused};
        use RestoreKind::{Ambiguous, Incompatible, Node, Request, Snapshot};
        let resource = |errno: i32| RESOURCE_ERRNOS.contains(&errno);
        match self {
            RestoreSite::RequestBody
            | RestoreSite::RequestFds
            | RestoreSite::VmExists
            | RestoreSite::VmMigrating
            | RestoreSite::SourceUrl
            | RestoreSite::MemoryZoneUpdate
            | RestoreSite::VmConfig
            | RestoreSite::Numa
            | RestoreSite::MemoryConfig
            | RestoreSite::DeviceConfig
            | RestoreSite::HandoffNotFileBacked
            | RestoreSite::LandlockPath => Request,

            RestoreSite::ConfigDecode
            | RestoreSite::StateDecode
            | RestoreSite::VmSection
            | RestoreSite::MemoryManagerState
            | RestoreSite::MemoryLayout
            | RestoreSite::UffdRanges
            | RestoreSite::UffdGpa
            | RestoreSite::DeviceState
            | RestoreSite::VcpuStateDecode => Snapshot,

            // Local files, hash-checked when the snapshot was pulled, and
            // the node's own descriptors, sockets and threads.
            RestoreSite::ConfigRead
            | RestoreSite::StateRead
            | RestoreSite::MemoryFile
            | RestoreSite::PayloadFile
            | RestoreSite::EventFdClone
            | RestoreSite::ConsoleSocketInUse
            | RestoreSite::DiskLock
            | RestoreSite::VcpuThreads
            | RestoreSite::VhostUserBackendConnect => Node,

            // The backend is the node's, decided by comparing what it offers
            // with what the snapshot needs.
            RestoreSite::CpuidCompatibility
            | RestoreSite::KvmExtensions
            | RestoreSite::UffdIoctls
            | RestoreSite::HeldClockUnpaired
            | RestoreSite::VhostUserBackendMismatch => Incompatible,

            RestoreSite::PageServerConnect | RestoreSite::Vmgenid | RestoreSite::Unexpected => {
                Ambiguous
            }

            // An errno from creating a device's descriptors, timers or
            // sockets is the node's; a device failing without one isn't
            // one the VMM can attribute.
            RestoreSite::ConsoleDevices
            | RestoreSite::DeviceCreate
            | RestoreSite::InterruptController => match evidence {
                Errno(_) => Node,
                HostLacks | Refused | Evidence::None => Ambiguous,
            },

            RestoreSite::Amx => match evidence {
                Errno(errno) if resource(errno) => Node,
                Errno(libc::EINVAL | libc::EOPNOTSUPP) | HostLacks => Incompatible,
                Errno(_) | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::SupportedCpuid => match evidence {
                Errno(errno) if resource(errno) || errno == libc::E2BIG => Node,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::KvmX2apic => match evidence {
                Errno(errno) if resource(errno) => Node,
                Errno(libc::EINVAL) => Incompatible,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::UffdCreate => match evidence {
                // EPERM: the node forbids unprivileged userfaultfds.
                Errno(errno) if resource(errno) || errno == libc::EPERM => Node,
                Errno(libc::EINVAL) => Incompatible,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::UffdRegister => match evidence {
                Errno(errno) if resource(errno) => Node,
                Errno(libc::EINVAL) => Incompatible,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::KvmCreateVcpu => match evidence {
                Errno(errno) if resource(errno) => Node,
                // An id the configuration shouldn't produce.
                Errno(libc::EINVAL) => Request,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::Landlock => match evidence {
                Errno(errno) if resource(errno) => Node,
                Errno(libc::ENOSYS | libc::EOPNOTSUPP) => Incompatible,
                Errno(libc::EINVAL) => Request,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },

            // A resource errno is the node's; any other failure here is one
            // the VMM can't attribute. For the page server's handoff, its
            // manager resolves that from the page server's recorded reason.
            RestoreSite::PageServerHandoff
            | RestoreSite::GuestMemory
            | RestoreSite::UffdHandler
            | RestoreSite::MemoryRestore
            | RestoreSite::CpuManager
            | RestoreSite::KvmCreateVm
            | RestoreSite::KvmIdentityMap
            | RestoreSite::KvmTss
            | RestoreSite::KvmSplitIrqchip
            | RestoreSite::KvmMemorySlot
            | RestoreSite::VmInit
            | RestoreSite::VcpuHostCapabilities
            | RestoreSite::KvmSetRegs
            | RestoreSite::KvmSetFpu
            | RestoreSite::VcpuState
            | RestoreSite::DirtyLogStart
            | RestoreSite::Resume => match evidence {
                Errno(errno) if resource(errno) => Node,
                Errno(_) | HostLacks | Refused | Evidence::None => Ambiguous,
            },

            // A state the kernel validates as content once every check of
            // the host's capabilities has passed.
            RestoreSite::KvmSetMpState
            | RestoreSite::KvmSetLapic
            | RestoreSite::KvmSetVcpuEvents => match evidence {
                Errno(errno) if resource(errno) => Node,
                HostLacks => Incompatible,
                Errno(libc::EINVAL) => Snapshot,
                Errno(_) | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::KvmSetCpuid2 => match evidence {
                Errno(errno) if resource(errno) => Node,
                // More entries than this host's KVM accepts.
                Errno(libc::E2BIG) | HostLacks => Incompatible,
                Errno(_) | Refused | Evidence::None => Ambiguous,
            },
            RestoreSite::KvmSetMsrs => match evidence {
                Errno(errno) if resource(errno) => Node,
                HostLacks => Incompatible,
                Refused => Snapshot,
                Errno(_) | Evidence::None => Ambiguous,
            },
            // The kernel's EINVAL for these depends on its version and the
            // host's microarchitecture as well as on the bytes, so once the
            // checks of the host's capabilities pass it is ambiguous; so is
            // KVM_SET_TSC_KHZ's EIO, which only a dead VM returns.
            RestoreSite::KvmSetSregs
            | RestoreSite::KvmSetXsave
            | RestoreSite::KvmSetXcrs
            | RestoreSite::KvmSetTscKhz
            | RestoreSite::KvmEnableSynic
            | RestoreSite::KvmSetNestedState
            | RestoreSite::KvmSetGuestSsp => match evidence {
                Errno(errno) if resource(errno) => Node,
                HostLacks => Incompatible,
                Errno(_) | Refused | Evidence::None => Ambiguous,
            },
        }
    }
}

impl fmt::Display for RestoreSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A failing site and what it found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cause {
    site: RestoreSite,
    evidence: Evidence,
    ioctl: Option<KvmIoctl>,
}

impl Cause {
    /// A failure at `site` with no evidence beyond it.
    fn at(site: RestoreSite) -> Self {
        Cause {
            site,
            evidence: Evidence::None,
            ioctl: None,
        }
    }

    /// A failure at `site` where a comparison with the host found a
    /// capability missing.
    fn host_lacks(site: RestoreSite) -> Self {
        Cause {
            evidence: Evidence::HostLacks,
            ..Cause::at(site)
        }
    }

    /// A failure at `site` with the errno and ioctl of the first error in
    /// `error`'s chain that carries one, found by downcasting each error
    /// in the chain to the types that carry them.
    fn chain(site: RestoreSite, error: &(dyn Error + 'static)) -> Self {
        let mut next = Some(error);
        while let Some(error) = next {
            let found = if let Some(HypervisorVmError::KvmIoctl { ioctl, source }) =
                error.downcast_ref()
            {
                Some((source.errno(), Some(*ioctl)))
            } else if let Some(HypervisorError::KvmIoctl { ioctl, source }) = error.downcast_ref() {
                Some((source.errno(), Some(*ioctl)))
            } else if let Some(HypervisorCpuError::SetVcpuState { ioctl, source }) =
                error.downcast_ref()
            {
                Some((source.errno(), Some(*ioctl)))
            } else if let Some(error) = error.downcast_ref::<io::Error>() {
                error.raw_os_error().map(|errno| (errno, None))
            } else {
                error
                    .downcast_ref::<errno::Error>()
                    .map(|error| (error.errno(), None))
            };
            if let Some((errno, ioctl)) = found {
                return Cause {
                    site,
                    evidence: Evidence::Errno(errno),
                    ioctl,
                };
            }
            next = error.source();
        }
        Cause::at(site)
    }

    fn of_vm_error(error: &VmError) -> Self {
        match error {
            VmError::VmAlreadyCreated => Cause::at(RestoreSite::VmExists),
            VmError::VmMigrating => Cause::at(RestoreSite::VmMigrating),
            VmError::InvalidRestoreSourceUrl => Cause::at(RestoreSite::SourceUrl),
            VmError::RecvSnapshot(error) => Cause::of_recv_error(error),
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            VmError::CpuidCompatibility(error) => Cause::of_cpuid_error(error),
            VmError::CreateConsoleDevices(error) => Cause::of_console_error(error),
            VmError::EventFdClone(error) => Cause::chain(RestoreSite::EventFdClone, error),
            VmError::HypervisorExtensions(_) => Cause::at(RestoreSite::KvmExtensions),
            VmError::CreateHypervisorVm(error) => Cause::of_create_vm_error(error),
            #[cfg(target_arch = "x86_64")]
            VmError::SetIdentityMapAddress(error) => {
                Cause::chain(RestoreSite::KvmIdentityMap, error)
            }
            #[cfg(target_arch = "x86_64")]
            VmError::SetTssAddress(error) => Cause::chain(RestoreSite::KvmTss, error),
            #[cfg(target_arch = "x86_64")]
            VmError::EnableSplitIrq(error) => Cause::chain(RestoreSite::KvmSplitIrqchip, error),
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            VmError::EnableX2ApicApi(error) => Cause::chain(RestoreSite::KvmX2apic, error),
            VmError::KernelFile(error)
            | VmError::InitramfsFile(error)
            | VmError::FirmwareFile(error) => Cause::chain(RestoreSite::PayloadFile, error),
            #[cfg(feature = "igvm")]
            VmError::IgvmLoad(error) => Cause::chain(RestoreSite::PayloadFile, error),
            VmError::ConfigValidation(_) | VmError::TooManyVsockDevices => {
                Cause::at(RestoreSite::VmConfig)
            }
            VmError::InvalidNumaConfig => Cause::at(RestoreSite::Numa),
            VmError::ApplyMemoryZoneUpdate(_) => Cause::at(RestoreSite::MemoryZoneUpdate),
            VmError::MemoryManager(error) => Cause::of_memory_manager_error(error),
            VmError::CpuManager(error) => Cause::of_cpu_error(error),
            VmError::DeviceManager(error) => Cause::of_device_manager_error(error),
            VmError::LockingError(error) => Cause::chain(RestoreSite::DiskLock, error),
            VmError::InitializeVm(error) => Cause::chain(RestoreSite::VmInit, error),
            VmError::HoldClockUnpaired => Cause::at(RestoreSite::HeldClockUnpaired),
            VmError::ApplyLandlock(error) => Cause::of_landlock_error(error),
            VmError::StartDirtyLog(error) => Cause::chain(RestoreSite::DirtyLogStart, error),
            VmError::Resume(error) => Cause::chain(RestoreSite::Resume, error),
            VmError::ResumeVm(error) => Cause::chain(RestoreSite::Resume, error),
            VmError::KernelLoad(_)
            | VmError::InitramfsLoad(_)
            | VmError::InitramfsAddress(_)
            | VmError::InitramfsRead(_)
            | VmError::LoadCmdLine(_)
            | VmError::CmdLineInsertStr(_)
            | VmError::CmdLineCreate(_)
            | VmError::ConfigureSystem(_)
            | VmError::NoDeviceToRemove(_)
            | VmError::SignalHandlerSpawn(_)
            | VmError::ThreadCleanup(_)
            | VmError::VmMissingConfig
            | VmError::VmNotCreated
            | VmError::VmNotRunning
            | VmError::VmRestoring
            | VmError::InvalidStateTransition(..)
            | VmError::Pause(_)
            | VmError::Snapshot(_)
            | VmError::SnapshotSend(_)
            | VmError::CaptureDirtyMemory(_)
            | VmError::DirtyPageCount(_)
            | VmError::LiveCheckpoint(_)
            | VmError::SettleMemory(_)
            | VmError::ReleaseVcpus(_)
            | VmError::SerializeJson(_)
            | VmError::CreateSeccompFilter(_)
            | VmError::ApplySeccompFilter(_)
            | VmError::ResizeZone
            | VmError::ResizeDisk
            | VmError::ActivateVirtioDevices(_)
            | VmError::PowerButton(_)
            | VmError::KernelMissingPvhHeader
            | VmError::KernelLoadThreadSpawn(_)
            | VmError::KernelLoadThreadJoin(_)
            | VmError::ErrorNmi(_)
            | VmError::CreatingAcpiTables(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            VmError::UefiLoad(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(feature = "sev_snp")]
            VmError::InitializeSevSnpVm(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(feature = "tdx")]
            VmError::LoadTdvf(_)
            | VmError::LoadPayload(_)
            | VmError::ParseTdvf(_)
            | VmError::PopulateHob(_)
            | VmError::AllocatingTdvfMemory(_)
            | VmError::InitializeTdxVm(_)
            | VmError::InitializeTdxMemoryRegion(_)
            | VmError::FinalizeTdx(_)
            | VmError::TdxFirmwareMissing
            | VmError::InvalidPayloadType => Cause::at(RestoreSite::Unexpected),
            #[cfg(feature = "guest_debug")]
            VmError::Debug(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
            VmError::Coredump(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(feature = "fw_cfg")]
            VmError::MissingFwCfgKernelFile(_)
            | VmError::MissingFwCfgInitramfs(_)
            | VmError::MissingFwCfgCmdline
            | VmError::AddingFwCfgItem(_)
            | VmError::ErrorPopulatingFwCfg(_)
            | VmError::FwCfgDisabled => Cause::at(RestoreSite::Unexpected),
        }
    }

    fn of_recv_error(error: &RecvError) -> Self {
        match error {
            RecvError::SourceUrl(_) => Cause::at(RestoreSite::SourceUrl),
            RecvError::Open { path, source } | RecvError::Read { path, source } => {
                let site = if path.ends_with(SNAPSHOT_CONFIG_FILE) {
                    RestoreSite::ConfigRead
                } else {
                    RestoreSite::StateRead
                };
                Cause::chain(site, source)
            }
            RecvError::Decode { path, .. } => Cause::at(if path.ends_with(SNAPSHOT_CONFIG_FILE) {
                RestoreSite::ConfigDecode
            } else {
                RestoreSite::StateDecode
            }),
            RecvError::MissingSection | RecvError::DecodeSection(_) => {
                Cause::at(RestoreSite::VmSection)
            }
        }
    }

    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn of_cpuid_error(error: &crate::CpuidCompatibilityError) -> Self {
        use hypervisor::arch::x86::AmxGuestSupportError;

        use crate::CpuidCompatibilityError;
        match error {
            #[cfg(feature = "tdx")]
            CpuidCompatibilityError::Tdx => Cause::at(RestoreSite::VmConfig),
            CpuidCompatibilityError::EnableAmx(
                HypervisorError::CouldNotEnableAmxStateComponents(error),
            ) => match error {
                AmxGuestSupportError::VendorDoesNotSupportAmx
                | AmxGuestSupportError::InvalidAmxTileFeatureCheck { .. } => {
                    Cause::host_lacks(RestoreSite::Amx)
                }
                AmxGuestSupportError::AmxNotSupported { errno }
                | AmxGuestSupportError::AmxGuestTileRequest { errno } => Cause {
                    evidence: i32::try_from(*errno).map_or(Evidence::None, Evidence::Errno),
                    ..Cause::at(RestoreSite::Amx)
                },
            },
            CpuidCompatibilityError::EnableAmx(error) => Cause::chain(RestoreSite::Amx, error),
            CpuidCompatibilityError::CommonCpuid(error) => {
                Cause::chain(RestoreSite::SupportedCpuid, error)
            }
            CpuidCompatibilityError::Incompatible(_) => Cause::at(RestoreSite::CpuidCompatibility),
        }
    }

    fn of_console_error(error: &ConsoleDeviceError) -> Self {
        match error {
            ConsoleDeviceError::CreateConsoleDevice(_)
            | ConsoleDeviceError::SetPtyRaw(_)
            | ConsoleDeviceError::DupFd(_)
            | ConsoleDeviceError::StartSigwinchListener(_) => {
                Cause::chain(RestoreSite::ConsoleDevices, error)
            }
            ConsoleDeviceError::SerialSocketInUse(_)
            | ConsoleDeviceError::ConsoleSocketInUse(_) => {
                Cause::at(RestoreSite::ConsoleSocketInUse)
            }
            ConsoleDeviceError::NoSocketOptionSupportForConsoleDevice
            | ConsoleDeviceError::MissingSocketPath => Cause::at(RestoreSite::VmConfig),
        }
    }

    fn of_create_vm_error(error: &HypervisorError) -> Self {
        match error {
            HypervisorError::CheckExtensions(_) => Cause::at(RestoreSite::KvmExtensions),
            HypervisorError::HypervisorAvailableCheck(_)
            | HypervisorError::HypervisorCreate(_)
            | HypervisorError::VmCreate(_)
            | HypervisorError::KvmIoctl { .. }
            | HypervisorError::GetMsrList(_)
            | HypervisorError::IncompatibleApiVersion
            | HypervisorError::TdxCapabilities(_)
            | HypervisorError::SetPartitionProperty(_)
            | HypervisorError::SevSnpCapabilities(_)
            | HypervisorError::GetFeatureMsrs(_)
            | HypervisorError::GetFeatureMsrsPartial => {
                Cause::chain(RestoreSite::KvmCreateVm, error)
            }
            #[cfg(target_arch = "x86_64")]
            HypervisorError::CouldNotEnableAmxStateComponents(_) => {
                Cause::chain(RestoreSite::KvmCreateVm, error)
            }
        }
    }

    fn of_landlock_error(error: &LandlockError) -> Self {
        match error {
            LandlockError::ManageRuleset(_) => Cause::chain(RestoreSite::Landlock, error),
            LandlockError::OpenPath(_) => Cause::chain(RestoreSite::LandlockPath, error),
            LandlockError::InvalidLandlockAccess(_) | LandlockError::InvalidPath => {
                Cause::at(RestoreSite::VmConfig)
            }
        }
    }

    fn of_memory_manager_error(error: &MemoryManagerError) -> Self {
        match error {
            MemoryManagerError::SharedFileCreate(_)
            | MemoryManagerError::SharedFileSetLen(_)
            | MemoryManagerError::SharedFileSeal(_)
            | MemoryManagerError::GuestMemory(_)
            | MemoryManagerError::GuestMemoryRegion(_)
            | MemoryManagerError::EventFdFail(_)
            | MemoryManagerError::ApplyNumaPolicy(_)
            | MemoryManagerError::GetFileSystemBlockSize(_)
            | MemoryManagerError::PrefaultMemory(_)
            | MemoryManagerError::CreateSystemAllocator => {
                Cause::chain(RestoreSite::GuestMemory, error)
            }
            #[cfg(target_arch = "x86_64")]
            MemoryManagerError::NewMmapRegion(_) => Cause::chain(RestoreSite::GuestMemory, error),
            MemoryManagerError::GuestRegionCollection(_)
            | MemoryManagerError::MemoryRangeAllocation
            | MemoryManagerError::NoSlotAvailable
            | MemoryManagerError::InvalidSize
            | MemoryManagerError::GuestAddressOverFlow
            | MemoryManagerError::AllocateMmioAddress => Cause::at(RestoreSite::MemoryLayout),
            MemoryManagerError::MissingMemoryZones
            | MemoryManagerError::InvalidMemoryParameters
            | MemoryManagerError::InvalidMemoryPath(_)
            | MemoryManagerError::InvalidResizeWithMemoryZones
            | MemoryManagerError::HotplugWhileDemandPaged
            | MemoryManagerError::SettleWithoutFaultSession
            | MemoryManagerError::InvalidResizeBelowBootSize(..)
            | MemoryManagerError::InvalidSharedMemoryZoneWithHostNuma
            | MemoryManagerError::DuplicateZoneId
            | MemoryManagerError::MissingVirtioMemHandler
            | MemoryManagerError::UnknownMemoryZone
            | MemoryManagerError::InvalidHotplugSize
            | MemoryManagerError::InvalidHotplugMethodWithMemoryZones
            | MemoryManagerError::MissingZoneIdentifier
            | MemoryManagerError::ResizeZone
            | MemoryManagerError::InsufficientHotplugRam(..)
            | MemoryManagerError::DirectoryAsBackingFileForMemory
            | MemoryManagerError::MisalignedMemorySize => Cause::at(RestoreSite::MemoryConfig),
            MemoryManagerError::CreateUserMemoryRegion(_)
            | MemoryManagerError::RemoveUserMemoryRegion(_) => {
                Cause::chain(RestoreSite::KvmMemorySlot, error)
            }
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            MemoryManagerError::CreateUefiFlash(_) => {
                Cause::chain(RestoreSite::KvmMemorySlot, error)
            }
            MemoryManagerError::RestoreSourceUrl(_)
            | MemoryManagerError::RestoreMissingSourceUrl => Cause::at(RestoreSite::SourceUrl),
            MemoryManagerError::RestoreStateDecode(_) => Cause::at(RestoreSite::MemoryManagerState),
            MemoryManagerError::Restore(MigratableError::OnDemandRestore(error)) => {
                Cause::of_uffd_error(error)
            }
            MemoryManagerError::Restore(error) => Cause::chain(RestoreSite::MemoryRestore, error),
            MemoryManagerError::HandoffNotFileBacked { .. } => {
                Cause::at(RestoreSite::HandoffNotFileBacked)
            }
            MemoryManagerError::FaultSession(_) | MemoryManagerError::SettleFaultSession(_) => {
                Cause::chain(RestoreSite::PageServerHandoff, error)
            }
            MemoryManagerError::SnapshotOpen(_)
            | MemoryManagerError::SnapshotRead(_)
            | MemoryManagerError::SnapshotCopy(_)
            | MemoryManagerError::SnapshotMmap(_) => Cause::chain(RestoreSite::MemoryFile, error),
            MemoryManagerError::VirtioMemResizeFail(_) => Cause::at(RestoreSite::Unexpected),
        }
    }

    fn of_uffd_error(error: &UffdError) -> Self {
        match error {
            UffdError::UnalignedRanges => Cause::at(RestoreSite::UffdRanges),
            UffdError::Create(_) => Cause::chain(RestoreSite::UffdCreate, error),
            UffdError::GpaTranslation { .. } => Cause::at(RestoreSite::UffdGpa),
            UffdError::Register { .. } => Cause::chain(RestoreSite::UffdRegister, error),
            UffdError::MissingIoctlSupport { .. } => Cause::at(RestoreSite::UffdIoctls),
            UffdError::SetSocket(_) => Cause::chain(RestoreSite::PageServerHandoff, error),
            UffdError::ConnectFaultSocket(_) => Cause::chain(RestoreSite::PageServerConnect, error),
            UffdError::SpawnThread(_) | UffdError::HandlerStartup | UffdError::HandlerFailed(_) => {
                Cause::chain(RestoreSite::UffdHandler, error)
            }
        }
    }

    fn of_cpu_error(error: &CpuError) -> Self {
        match error {
            CpuError::VcpuCreate(_) => Cause::chain(RestoreSite::KvmCreateVcpu, error),
            CpuError::VcpuStateDecode { .. } => Cause::at(RestoreSite::VcpuStateDecode),
            CpuError::VcpuStateRestore { source, .. } => Cause::of_vcpu_state_error(source),
            CpuError::StartRestoreVcpu(error) => Cause::of_cpu_error(error),
            CpuError::VcpuSpawn(_) | CpuError::CoreScheduling(_) => {
                Cause::chain(RestoreSite::VcpuThreads, error)
            }
            CpuError::EventFdClone(_) => Cause::chain(RestoreSite::EventFdClone, error),
            CpuError::CommonCpuId(_)
            | CpuError::VcpuConfiguration(_)
            | CpuError::MsrConfigurationUpdate(_)
            | CpuError::BusError(_) => Cause::chain(RestoreSite::CpuManager, error),
            #[cfg(target_arch = "x86_64")]
            CpuError::AmxEnable(_) => Cause::chain(RestoreSite::CpuManager, error),
            CpuError::DesiredVCpuCountIsZero
            | CpuError::DesiredVCpuCountExceedsMax
            | CpuError::MaximumVcpusExceeded(..) => Cause::at(RestoreSite::VmConfig),
            CpuError::VcpuRun(_)
            | CpuError::VcpuPendingRemovedVcpu
            | CpuError::ThreadCleanup(_)
            | CpuError::SignalAcknowledgeTimeout
            | CpuError::VcpuGate(_)
            | CpuError::CreateSeccompFilter(_)
            | CpuError::ApplySeccompFilter(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(target_arch = "aarch64")]
            CpuError::VcpuArmPreferredTarget(_)
            | CpuError::VcpuSetProcessorFeatures(_)
            | CpuError::VcpuArmInit(_)
            | CpuError::VcpuArmFinalize(_)
            | CpuError::VcpuSetPreFinalizeRegs(_)
            | CpuError::VcpuSetGicrBaseAddr(_)
            | CpuError::InitPmu(_) => Cause::chain(RestoreSite::VcpuState, error),
            #[cfg(feature = "tdx")]
            CpuError::InitializeTdx(_) => Cause::at(RestoreSite::Unexpected),
            #[cfg(feature = "guest_debug")]
            CpuError::CpuDebug(_) | CpuError::TranslateVirtualAddress(_) => {
                Cause::at(RestoreSite::Unexpected)
            }
            #[cfg(feature = "sev_snp")]
            CpuError::SetSevControlRegister(_) | CpuError::SetupSevSnpRegs(_) => {
                Cause::at(RestoreSite::Unexpected)
            }
            #[cfg(feature = "mshv")]
            CpuError::SetPartitionProperty(_) => Cause::at(RestoreSite::Unexpected),
        }
    }

    fn of_vcpu_state_error(error: &HypervisorCpuError) -> Self {
        match error {
            HypervisorCpuError::SetVcpuState { ioctl, .. } => {
                let site = match ioctl {
                    KvmIoctl::SetCpuid2 => RestoreSite::KvmSetCpuid2,
                    KvmIoctl::SetMpState => RestoreSite::KvmSetMpState,
                    KvmIoctl::SetRegs => RestoreSite::KvmSetRegs,
                    KvmIoctl::SetSregs => RestoreSite::KvmSetSregs,
                    KvmIoctl::SetXsave => RestoreSite::KvmSetXsave,
                    KvmIoctl::SetXcrs => RestoreSite::KvmSetXcrs,
                    KvmIoctl::SetLapic => RestoreSite::KvmSetLapic,
                    KvmIoctl::SetFpu => RestoreSite::KvmSetFpu,
                    KvmIoctl::SetTscKhz => RestoreSite::KvmSetTscKhz,
                    KvmIoctl::EnableCap => RestoreSite::KvmEnableSynic,
                    KvmIoctl::SetMsrs => RestoreSite::KvmSetMsrs,
                    KvmIoctl::SetNestedState => RestoreSite::KvmSetNestedState,
                    KvmIoctl::SetOneReg => RestoreSite::KvmSetGuestSsp,
                    KvmIoctl::SetVcpuEvents => RestoreSite::KvmSetVcpuEvents,
                    KvmIoctl::GetSupportedCpuid | KvmIoctl::GetTscKhz => {
                        RestoreSite::VcpuHostCapabilities
                    }
                    KvmIoctl::CreateVm
                    | KvmIoctl::GetMsrIndexList
                    | KvmIoctl::SetIdentityMapAddr
                    | KvmIoctl::SetTssAddr
                    | KvmIoctl::CreateVcpu
                    | KvmIoctl::SetUserMemoryRegion
                    | KvmIoctl::SetClock => RestoreSite::VcpuState,
                };
                Cause::chain(site, error)
            }
            #[cfg(target_arch = "x86_64")]
            HypervisorCpuError::RestoreMsr { refusal, .. } => match refusal {
                MsrRefusal::NotListed
                | MsrRefusal::FeatureValue
                | MsrRefusal::Value(MsrValueCheck::Host) => {
                    Cause::host_lacks(RestoreSite::KvmSetMsrs)
                }
                MsrRefusal::Value(MsrValueCheck::Content) => Cause {
                    evidence: Evidence::Refused,
                    ..Cause::at(RestoreSite::KvmSetMsrs)
                },
                MsrRefusal::Value(MsrValueCheck::Unattributable | MsrValueCheck::Unexamined) => {
                    Cause::at(RestoreSite::KvmSetMsrs)
                }
            },
            #[cfg(target_arch = "x86_64")]
            HypervisorCpuError::IncompatibleVcpuState(incompatible) => {
                Cause::host_lacks(match incompatible {
                    IncompatibleVcpuState::TscRate { .. } => RestoreSite::KvmSetTscKhz,
                    IncompatibleVcpuState::Cr4 { .. } => RestoreSite::KvmSetSregs,
                    IncompatibleVcpuState::XsaveComponents { .. } => RestoreSite::KvmSetXsave,
                    IncompatibleVcpuState::Xcr0 { .. } => RestoreSite::KvmSetXcrs,
                    IncompatibleVcpuState::HypervSynic => RestoreSite::KvmEnableSynic,
                    IncompatibleVcpuState::NestedState { .. } => RestoreSite::KvmSetNestedState,
                    IncompatibleVcpuState::ShadowStack => RestoreSite::KvmSetGuestSsp,
                    IncompatibleVcpuState::VcpuEvents { .. } | IncompatibleVcpuState::Smm => {
                        RestoreSite::KvmSetVcpuEvents
                    }
                })
            }
            HypervisorCpuError::MalformedVcpuState(_) => Cause::at(RestoreSite::VcpuStateDecode),
            HypervisorCpuError::SetStandardRegs(_)
            | HypervisorCpuError::GetStandardRegs(_)
            | HypervisorCpuError::SetSpecialRegs(_)
            | HypervisorCpuError::GetSpecialRegs(_)
            | HypervisorCpuError::SetFloatingPointRegs(_)
            | HypervisorCpuError::GetFloatingPointRegs(_)
            | HypervisorCpuError::SetCpuid(_)
            | HypervisorCpuError::GetCpuid(_)
            | HypervisorCpuError::SetLapicState(_)
            | HypervisorCpuError::GetlapicState(_)
            | HypervisorCpuError::SetMsrEntries(_)
            | HypervisorCpuError::GetMsrEntries(_)
            | HypervisorCpuError::SetMpState(_)
            | HypervisorCpuError::GetMpState(_)
            | HypervisorCpuError::SetXcsr(_)
            | HypervisorCpuError::GetXcsr(_)
            | HypervisorCpuError::RunVcpu(_)
            | HypervisorCpuError::GetVcpuEvents(_)
            | HypervisorCpuError::SetVcpuEvents(_)
            | HypervisorCpuError::VcpuInit(_)
            | HypervisorCpuError::VcpuFinalize(_)
            | HypervisorCpuError::SetRegister(_)
            | HypervisorCpuError::GetRegister(_)
            | HypervisorCpuError::NotifyGuestClockPaused(_)
            | HypervisorCpuError::SetDebugRegs(_)
            | HypervisorCpuError::GetDebugRegs(_)
            | HypervisorCpuError::SetMiscRegs(_)
            | HypervisorCpuError::GetMiscRegs(_)
            | HypervisorCpuError::EnableHyperVSyncIc(_)
            | HypervisorCpuError::GetAarchCoreRegister(_)
            | HypervisorCpuError::SetAarchCoreRegister(_)
            | HypervisorCpuError::GetExtendedRegister(_)
            | HypervisorCpuError::SetExtendedRegister(_)
            | HypervisorCpuError::GetRiscvCoreRegister(_)
            | HypervisorCpuError::SetRiscvCoreRegister(_)
            | HypervisorCpuError::GetRegList(_)
            | HypervisorCpuError::GetSysRegister(_)
            | HypervisorCpuError::SetSysRegister(_)
            | HypervisorCpuError::GetNonCoreRegister(_)
            | HypervisorCpuError::TranslateVirtualAddress(_)
            | HypervisorCpuError::GpaWrite(_)
            | HypervisorCpuError::GetCpuidVales(_)
            | HypervisorCpuError::Nmi(_)
            | HypervisorCpuError::GetNestedState(_) => Cause::chain(RestoreSite::VcpuState, error),
            #[cfg(feature = "kvm")]
            HypervisorCpuError::GetXsaveState(_) => Cause::chain(RestoreSite::VcpuState, error),
            #[cfg(feature = "mshv")]
            HypervisorCpuError::GetAllVpStateComponents(_)
            | HypervisorCpuError::SetAllVpStateComponents(_) => {
                Cause::chain(RestoreSite::VcpuState, error)
            }
            #[cfg(feature = "tdx")]
            HypervisorCpuError::InitializeTdx(_) | HypervisorCpuError::UnknownTdxVmCall => {
                Cause::chain(RestoreSite::VcpuState, error)
            }
            #[cfg(target_arch = "aarch64")]
            HypervisorCpuError::InitializePmu(_) | HypervisorCpuError::UnsupportedSysReg(_) => {
                Cause::chain(RestoreSite::VcpuState, error)
            }
            #[cfg(target_arch = "x86_64")]
            HypervisorCpuError::GetTscKhz(_)
            | HypervisorCpuError::GetTscOffset(_)
            | HypervisorCpuError::SetTscOffset(_) => Cause::chain(RestoreSite::VcpuState, error),
            #[cfg(feature = "sev_snp")]
            HypervisorCpuError::SetSevControlRegister(_) => {
                Cause::chain(RestoreSite::VcpuState, error)
            }
        }
    }

    fn of_device_manager_error(error: &DeviceManagerError) -> Self {
        match error {
            DeviceManagerError::RestoreGetState(_) => Cause::at(RestoreSite::DeviceState),
            DeviceManagerError::MemoryManager(error) => Cause::of_memory_manager_error(error),
            DeviceManagerError::CreateInterruptController(_) => {
                Cause::chain(RestoreSite::InterruptController, error)
            }
            DeviceManagerError::DiskLockError(_) => Cause::chain(RestoreSite::DiskLock, error),
            DeviceManagerError::HotplugStartDirtyLog(_) => {
                Cause::chain(RestoreSite::DirtyLogStart, error)
            }
            #[cfg(not(target_arch = "riscv64"))]
            DeviceManagerError::VmGenId(_) | DeviceManagerError::VmGenIdNotification(_) => {
                Cause::chain(RestoreSite::Vmgenid, error)
            }
            DeviceManagerError::IommufdNotSupported
            | DeviceManagerError::NoDevicePassthroughSupport => {
                Cause::host_lacks(RestoreSite::DeviceCreate)
            }
            DeviceManagerError::GuestBlockSizeBelowBackend
            | DeviceManagerError::NoVirtioFsSock
            | DeviceManagerError::NoGenericVhostUserSock
            | DeviceManagerError::CreateVdpaConvertPath
            | DeviceManagerError::CreateVsockConvertPath
            | DeviceManagerError::PmemRangeAllocation
            | DeviceManagerError::ExpectedIommufdBackend
            | DeviceManagerError::NoAvailableDeviceName
            | DeviceManagerError::RemovalNotAllowed(_)
            | DeviceManagerError::UnknownDeviceId(_)
            | DeviceManagerError::NoDiskPath
            | DeviceManagerError::PmemWithDirectorySizeMissing
            | DeviceManagerError::PmemSizeNotAligned
            | DeviceManagerError::MissingVirtioBalloon
            | DeviceManagerError::MissingVirtualIommu
            | DeviceManagerError::InvalidIommuHotplug
            | DeviceManagerError::InvalidIommuRemove(_)
            | DeviceManagerError::IdentifierNotUnique(_)
            | DeviceManagerError::InvalidIdentifier(_)
            | DeviceManagerError::UserDeviceSocketInUse(_) => Cause::at(RestoreSite::DeviceConfig),
            #[cfg(all(target_arch = "aarch64", feature = "kvm"))]
            DeviceManagerError::IommufdDevIdMissing => Cause::at(RestoreSite::DeviceConfig),
            DeviceManagerError::EventFd(_)
            | DeviceManagerError::Disk(_)
            | DeviceManagerError::CreateVhostUserNet(_)
            | DeviceManagerError::CreateVirtioBlock(_)
            | DeviceManagerError::CreateVirtioNet(_)
            | DeviceManagerError::CreateVirtioConsole(_)
            | DeviceManagerError::CreateVirtioRng(_)
            | DeviceManagerError::CreateVirtioRtc(_)
            | DeviceManagerError::CreateGenericVhostUser(_)
            | DeviceManagerError::CreateVirtioFs(_)
            | DeviceManagerError::CreateVirtioPmem(_)
            | DeviceManagerError::CreateVdpa(_)
            | DeviceManagerError::CreateVirtioVsock(_)
            | DeviceManagerError::CreateTpmDevice(_)
            | DeviceManagerError::CreateVsockBackend(_)
            | DeviceManagerError::CreateVirtioIommu(_)
            | DeviceManagerError::CreateVirtioBalloon(_)
            | DeviceManagerError::CreateVirtioWatchdog(_)
            | DeviceManagerError::CreateSerialManager(_)
            | DeviceManagerError::SpawnSerialManager(_)
            | DeviceManagerError::AllocateIrq(_)
            | DeviceManagerError::AllocateBars(_)
            | DeviceManagerError::FreePciBars(_)
            | DeviceManagerError::RegisterIoevent(_)
            | DeviceManagerError::UnRegisterIoevent(_)
            | DeviceManagerError::VirtioDevice(_)
            | DeviceManagerError::AddPciDevice(_)
            | DeviceManagerError::PioInsert(_)
            | DeviceManagerError::MmioInsert(_)
            | DeviceManagerError::PmemFileOpen(_)
            | DeviceManagerError::PmemFileSetLen(_)
            | DeviceManagerError::VfioCreate(_)
            | DeviceManagerError::VfioDupFd(_)
            | DeviceManagerError::VfioPciCreate(_)
            | DeviceManagerError::VfioMapRegion(_)
            | DeviceManagerError::VfioDmaMap(..)
            | DeviceManagerError::CreatePassthroughDevice(_)
            | DeviceManagerError::BusError(_)
            | DeviceManagerError::AllocateIoPort
            | DeviceManagerError::AllocateMmioAddress
            | DeviceManagerError::HotPlugNotification(_)
            | DeviceManagerError::CreateInterruptGroup(_)
            | DeviceManagerError::NewMmapRegion(_)
            | DeviceManagerError::CloneFile(_)
            | DeviceManagerError::MissingPciDevice
            | DeviceManagerError::RemoveDeviceFromPciBus(_)
            | DeviceManagerError::RemoveDeviceFromIoBus(_)
            | DeviceManagerError::RemoveDeviceFromMmioBus(_)
            | DeviceManagerError::AllocatePciDeviceId(_)
            | DeviceManagerError::ReservePciDeviceId(_)
            | DeviceManagerError::FreePciDeviceId(_)
            | DeviceManagerError::UpdateMemoryForVirtioDevice(_)
            | DeviceManagerError::CreateVirtioMem(_)
            | DeviceManagerError::UpdateMemoryForVfioPciDevice(_)
            | DeviceManagerError::MissingNode
            | DeviceManagerError::ResourceAlreadyExists
            | DeviceManagerError::MissingVirtioPmemResources
            | DeviceManagerError::MissingDeviceNodePciBdf
            | DeviceManagerError::VirtioBalloonResize(_)
            | DeviceManagerError::VirtioBalloonStats(_)
            | DeviceManagerError::PowerButtonNotification(_)
            | DeviceManagerError::AddDmaMappingHandlerVirtioMem(_)
            | DeviceManagerError::RemoveDmaMappingHandlerVirtioMem(_)
            | DeviceManagerError::VfioUserCreateClient(_)
            | DeviceManagerError::VfioUserCreate(_)
            | DeviceManagerError::VfioUserMapRegion(_)
            | DeviceManagerError::VfioUserDmaMap(_)
            | DeviceManagerError::UpdateMemoryForVfioUserPciDevice(_)
            | DeviceManagerError::DupFd(_)
            | DeviceManagerError::VirtioDmaMap(_)
            | DeviceManagerError::VirtioDmaUnmap(_)
            | DeviceManagerError::PvPanicCreate(_)
            | DeviceManagerError::RateLimiterGroupCreate(_)
            | DeviceManagerError::InvalidConsoleInfo
            | DeviceManagerError::DiskResize(_) => Cause::chain(RestoreSite::DeviceCreate, error),
            DeviceManagerError::CreateVhostUserBlk(source) => match source {
                vhost_user::Error::RestoreConnect { .. } => {
                    Cause::at(RestoreSite::VhostUserBackendConnect)
                }
                vhost_user::Error::RestoredConfigMismatch { .. }
                | vhost_user::Error::RestoredFeaturesUnsupported { .. }
                | vhost_user::Error::UnsupportedProtocolFeatures(_) => {
                    Cause::at(RestoreSite::VhostUserBackendMismatch)
                }
                // Every other failure to create a vhost-user-blk device,
                // as for every other device.
                _ => Cause::chain(RestoreSite::DeviceCreate, error),
            },
            #[cfg(feature = "kvm")]
            DeviceManagerError::IommufdCreate(_) => Cause::chain(RestoreSite::DeviceCreate, error),
            #[cfg(all(target_arch = "aarch64", feature = "kvm"))]
            DeviceManagerError::Smmuv3(_) | DeviceManagerError::FindPhysicalIommu(_) => {
                Cause::chain(RestoreSite::DeviceCreate, error)
            }
            #[cfg(target_arch = "aarch64")]
            DeviceManagerError::AArch64PowerButtonNotification(_) => {
                Cause::chain(RestoreSite::DeviceCreate, error)
            }
            #[cfg(all(feature = "kvm", feature = "sev_snp", feature = "fw_cfg"))]
            DeviceManagerError::AddDmaMappingHandlerSevSnp(_)
            | DeviceManagerError::VfioUserHotplugSevSnpTracker => {
                Cause::chain(RestoreSite::DeviceCreate, error)
            }
            #[cfg(feature = "ivshmem")]
            DeviceManagerError::IvshmemCreate(_) => Cause::chain(RestoreSite::DeviceCreate, error),
            #[cfg(feature = "fw_cfg")]
            DeviceManagerError::ErrorAddingFwCfgToBus(_) => {
                Cause::chain(RestoreSite::DeviceCreate, error)
            }
        }
    }
}

/// A failed `vm.restore`: where it failed, with the errno and ioctl when
/// the site is a system call or an ioctl, the kind those give, and the
/// error the site returned.
///
/// It displays as that error and has its sources, so a restore's error
/// reads the same with or without the classification.
#[derive(Debug)]
pub struct RestoreFailure {
    site: RestoreSite,
    kind: RestoreKind,
    errno: Option<i32>,
    ioctl: Option<KvmIoctl>,
    error: Box<dyn Error + Send>,
}

impl RestoreFailure {
    fn new(cause: Cause, error: Box<dyn Error + Send>) -> Self {
        let errno = match cause.evidence {
            Evidence::Errno(errno) => Some(errno),
            Evidence::HostLacks | Evidence::Refused | Evidence::None => None,
        };
        RestoreFailure {
            site: cause.site,
            kind: cause.site.classify(cause.evidence),
            errno,
            ioctl: cause.ioctl,
            error,
        }
    }

    /// Classifies an error the VMM's restore path returned.
    pub fn of_vm_error(error: VmError) -> Self {
        RestoreFailure::new(Cause::of_vm_error(&error), Box::new(error))
    }

    /// A restore request whose body or file descriptors the API couldn't
    /// accept, at `site`.
    pub fn of_request(site: RestoreSite, error: Box<dyn Error + Send>) -> Self {
        RestoreFailure::new(Cause::at(site), error)
    }

    /// Where the restore failed.
    pub fn site(&self) -> RestoreSite {
        self.site
    }

    /// Whose fault the failure is.
    pub fn kind(&self) -> RestoreKind {
        self.kind
    }

    /// The errno of the failed system call or ioctl, when the site is one.
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }

    /// The KVM ioctl that failed, when the site is one.
    pub fn ioctl(&self) -> Option<KvmIoctl> {
        self.ioctl
    }

    /// The error the failing site returned.
    pub fn error(&self) -> &(dyn Error + Send + 'static) {
        self.error.as_ref()
    }

    /// The headers a `vm.restore` error response carries: `Restore-Kind`
    /// and `Restore-Site` always, and `Restore-Errno`, in decimal, and
    /// `Restore-Ioctl` when the site has them.
    pub fn response_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::from([
            ("Restore-Kind".to_owned(), self.kind.name().to_owned()),
            ("Restore-Site".to_owned(), self.site.name().to_owned()),
        ]);
        if let Some(errno) = self.errno {
            headers.insert("Restore-Errno".to_owned(), errno.to_string());
        }
        if let Some(ioctl) = self.ioctl {
            headers.insert("Restore-Ioctl".to_owned(), ioctl.name().to_owned());
        }
        headers
    }
}

impl fmt::Display for RestoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl Error for RestoreFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.error.source()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::anyhow;

    use super::*;
    use crate::migration::SNAPSHOT_STATE_FILE;

    /// Every evidence a site can be given.
    const EVIDENCE: [Evidence; 6] = [
        Evidence::Errno(libc::ENOMEM),
        Evidence::Errno(libc::EINVAL),
        Evidence::Errno(libc::EIO),
        Evidence::HostLacks,
        Evidence::Refused,
        Evidence::None,
    ];

    /// The kind each site gives each evidence, written out per site. The
    /// match has no wildcard, so a site added without its row here doesn't
    /// compile.
    fn table(site: RestoreSite) -> Vec<(Evidence, RestoreKind)> {
        use Evidence::{Errno, HostLacks, Refused};
        use RestoreKind::{Ambiguous, Incompatible, Node, Request, Snapshot};
        let always = |kind| EVIDENCE.iter().map(|&evidence| (evidence, kind)).collect();
        let errno_is_node = vec![
            (Errno(libc::ENOMEM), Node),
            (Errno(libc::EMFILE), Node),
            (Errno(libc::EINVAL), Node),
            (Errno(libc::EIO), Node),
            (HostLacks, Ambiguous),
            (Refused, Ambiguous),
            (Evidence::None, Ambiguous),
        ];
        let resources_are_node = vec![
            (Errno(libc::ENOMEM), Node),
            (Errno(libc::EMFILE), Node),
            (Errno(libc::ENFILE), Node),
            (Errno(libc::EAGAIN), Node),
            (Errno(libc::ENOSPC), Node),
            (Errno(libc::EINVAL), Ambiguous),
            (Errno(libc::EEXIST), Ambiguous),
            (Errno(libc::EPIPE), Ambiguous),
            (Errno(libc::ECONNRESET), Ambiguous),
            (HostLacks, Ambiguous),
            (Refused, Ambiguous),
            (Evidence::None, Ambiguous),
        ];
        let checked_then_ambiguous = vec![
            (Errno(libc::ENOMEM), Node),
            (HostLacks, Incompatible),
            (Errno(libc::EINVAL), Ambiguous),
            (Errno(libc::EIO), Ambiguous),
            (Refused, Ambiguous),
            (Evidence::None, Ambiguous),
        ];
        let checked_then_content = vec![
            (Errno(libc::ENOMEM), Node),
            (HostLacks, Incompatible),
            (Errno(libc::EINVAL), Snapshot),
            (Errno(libc::EIO), Ambiguous),
            (Refused, Ambiguous),
            (Evidence::None, Ambiguous),
        ];
        match site {
            RestoreSite::RequestBody
            | RestoreSite::RequestFds
            | RestoreSite::VmExists
            | RestoreSite::VmMigrating
            | RestoreSite::SourceUrl
            | RestoreSite::MemoryZoneUpdate
            | RestoreSite::VmConfig
            | RestoreSite::Numa
            | RestoreSite::MemoryConfig
            | RestoreSite::DeviceConfig
            | RestoreSite::HandoffNotFileBacked
            | RestoreSite::LandlockPath => always(Request),
            RestoreSite::ConfigDecode
            | RestoreSite::StateDecode
            | RestoreSite::VmSection
            | RestoreSite::MemoryManagerState
            | RestoreSite::MemoryLayout
            | RestoreSite::UffdRanges
            | RestoreSite::UffdGpa
            | RestoreSite::DeviceState
            | RestoreSite::VcpuStateDecode => always(Snapshot),
            RestoreSite::ConfigRead
            | RestoreSite::StateRead
            | RestoreSite::MemoryFile
            | RestoreSite::PayloadFile
            | RestoreSite::EventFdClone
            | RestoreSite::ConsoleSocketInUse
            | RestoreSite::DiskLock
            | RestoreSite::VcpuThreads
            | RestoreSite::VhostUserBackendConnect => always(Node),
            RestoreSite::CpuidCompatibility
            | RestoreSite::KvmExtensions
            | RestoreSite::UffdIoctls
            | RestoreSite::HeldClockUnpaired
            | RestoreSite::VhostUserBackendMismatch => always(Incompatible),
            RestoreSite::PageServerConnect | RestoreSite::Vmgenid | RestoreSite::Unexpected => {
                always(Ambiguous)
            }
            RestoreSite::ConsoleDevices
            | RestoreSite::DeviceCreate
            | RestoreSite::InterruptController => errno_is_node,
            RestoreSite::Amx => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::EINVAL), Incompatible),
                (Errno(libc::EOPNOTSUPP), Incompatible),
                (HostLacks, Incompatible),
                (Errno(libc::EIO), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::SupportedCpuid => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::E2BIG), Node),
                (Errno(libc::EINVAL), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::KvmX2apic => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::EINVAL), Incompatible),
                (Errno(libc::EIO), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::UffdCreate => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::EMFILE), Node),
                (Errno(libc::EPERM), Node),
                (Errno(libc::EINVAL), Incompatible),
                (Errno(libc::EIO), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::UffdRegister => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::EINVAL), Incompatible),
                (Errno(libc::EIO), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::KvmCreateVcpu => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::EMFILE), Node),
                (Errno(libc::ENFILE), Node),
                (Errno(libc::EINVAL), Request),
                (Errno(libc::EEXIST), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::Landlock => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::ENOSYS), Incompatible),
                (Errno(libc::EOPNOTSUPP), Incompatible),
                (Errno(libc::EINVAL), Request),
                (Errno(libc::EIO), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::PageServerHandoff
            | RestoreSite::GuestMemory
            | RestoreSite::UffdHandler
            | RestoreSite::MemoryRestore
            | RestoreSite::CpuManager
            | RestoreSite::KvmCreateVm
            | RestoreSite::KvmIdentityMap
            | RestoreSite::KvmTss
            | RestoreSite::KvmSplitIrqchip
            | RestoreSite::KvmMemorySlot
            | RestoreSite::VmInit
            | RestoreSite::VcpuHostCapabilities
            | RestoreSite::KvmSetRegs
            | RestoreSite::KvmSetFpu
            | RestoreSite::VcpuState
            | RestoreSite::DirtyLogStart
            | RestoreSite::Resume => resources_are_node,
            RestoreSite::KvmSetMpState
            | RestoreSite::KvmSetLapic
            | RestoreSite::KvmSetVcpuEvents => checked_then_content,
            RestoreSite::KvmSetCpuid2 => vec![
                (Errno(libc::ENOMEM), Node),
                (Errno(libc::E2BIG), Incompatible),
                (HostLacks, Incompatible),
                (Errno(libc::EINVAL), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::KvmSetMsrs => vec![
                (Errno(libc::ENOMEM), Node),
                (HostLacks, Incompatible),
                (Refused, Snapshot),
                (Errno(libc::EINVAL), Ambiguous),
                (Evidence::None, Ambiguous),
            ],
            RestoreSite::KvmSetSregs
            | RestoreSite::KvmSetXsave
            | RestoreSite::KvmSetXcrs
            | RestoreSite::KvmSetTscKhz
            | RestoreSite::KvmEnableSynic
            | RestoreSite::KvmSetNestedState
            | RestoreSite::KvmSetGuestSsp => checked_then_ambiguous,
        }
    }

    #[test]
    fn test_every_site_classifies_as_its_table_row_says() {
        for &site in RestoreSite::ALL {
            for (evidence, kind) in table(site) {
                assert_eq!(site.classify(evidence), kind, "{site} with {evidence:?}");
            }
        }
    }

    #[test]
    fn test_restored_vhost_user_backend_faults_are_the_hosts() {
        let blk = |source| VmError::DeviceManager(DeviceManagerError::CreateVhostUserBlk(source));
        assert_eq!(
            classified(blk(vhost_user::Error::RestoreConnect {
                id: "base".to_owned(),
                socket: "/vm/vblk-base.sock".to_owned(),
                source: Box::new(vhost_user::Error::VhostUserConnectTimeout),
            })),
            (
                RestoreSite::VhostUserBackendConnect,
                RestoreKind::Node,
                None,
                None
            )
        );
        for source in [
            vhost_user::Error::RestoredConfigMismatch {
                id: "scratch".to_owned(),
                field: "capacity",
                saved: 2048,
                backend: 4096,
            },
            vhost_user::Error::RestoredFeaturesUnsupported {
                id: "base".to_owned(),
                missing: 1 << 5,
            },
            vhost_user::Error::UnsupportedProtocolFeatures(1 << 9),
        ] {
            assert_eq!(
                classified(blk(source)),
                (
                    RestoreSite::VhostUserBackendMismatch,
                    RestoreKind::Incompatible,
                    None,
                    None
                )
            );
        }
        assert_eq!(
            classified(blk(vhost_user::Error::BadQueueNum)).0,
            RestoreSite::DeviceCreate,
            "another failure to create the device is still the device's"
        );
    }

    #[test]
    fn test_site_names_are_unique_and_wire_safe() {
        let mut names: Vec<&str> = RestoreSite::ALL.iter().map(|site| site.name()).collect();
        assert!(names.iter().all(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }));
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    fn vcpu_state(source: HypervisorCpuError) -> VmError {
        VmError::CpuManager(CpuError::VcpuStateRestore { id: 1, source })
    }

    fn os_error(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    /// The site, kind, errno and ioctl a restore that failed with `error`
    /// reports.
    fn classified(error: VmError) -> (RestoreSite, RestoreKind, Option<i32>, Option<KvmIoctl>) {
        let failure = RestoreFailure::of_vm_error(error);
        (
            failure.site(),
            failure.kind(),
            failure.errno(),
            failure.ioctl(),
        )
    }

    #[test]
    fn test_snapshot_files_are_classified_by_which_file_and_how_they_failed() {
        let decode = serde_json::from_slice::<u32>(b"{").unwrap_err();
        assert_eq!(
            classified(VmError::RecvSnapshot(RecvError::Decode {
                path: PathBuf::from("/snapshot").join(SNAPSHOT_CONFIG_FILE),
                source: decode,
            })),
            (RestoreSite::ConfigDecode, RestoreKind::Snapshot, None, None)
        );
        assert_eq!(
            classified(VmError::RecvSnapshot(RecvError::Open {
                path: PathBuf::from("/snapshot").join(SNAPSHOT_STATE_FILE),
                source: os_error(libc::ENOENT),
            })),
            (
                RestoreSite::StateRead,
                RestoreKind::Node,
                Some(libc::ENOENT),
                None
            )
        );
        assert_eq!(
            classified(VmError::RecvSnapshot(RecvError::MissingSection)),
            (RestoreSite::VmSection, RestoreKind::Snapshot, None, None)
        );
    }

    #[test]
    fn test_vcpu_ioctls_carry_their_errno_and_ioctl() {
        let set_sregs = |errno| {
            vcpu_state(HypervisorCpuError::SetVcpuState {
                ioctl: KvmIoctl::SetSregs,
                source: errno::Error::new(errno),
            })
        };
        assert_eq!(
            classified(set_sregs(libc::EINVAL)),
            (
                RestoreSite::KvmSetSregs,
                RestoreKind::Ambiguous,
                Some(libc::EINVAL),
                Some(KvmIoctl::SetSregs)
            )
        );
        assert_eq!(classified(set_sregs(libc::ENOMEM)).1, RestoreKind::Node);
        assert_eq!(
            classified(vcpu_state(HypervisorCpuError::SetVcpuState {
                ioctl: KvmIoctl::SetLapic,
                source: errno::Error::new(libc::EINVAL),
            })),
            (
                RestoreSite::KvmSetLapic,
                RestoreKind::Snapshot,
                Some(libc::EINVAL),
                Some(KvmIoctl::SetLapic)
            )
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_host_capability_checks_and_refused_msrs_are_classified() {
        use hypervisor::arch::x86::msr_index::MSR_K7_HWCR;

        assert_eq!(
            classified(vcpu_state(HypervisorCpuError::IncompatibleVcpuState(
                IncompatibleVcpuState::Cr4 { bits: 1 << 12 }
            ))),
            (
                RestoreSite::KvmSetSregs,
                RestoreKind::Incompatible,
                None,
                None
            )
        );
        assert_eq!(
            classified(vcpu_state(HypervisorCpuError::IncompatibleVcpuState(
                IncompatibleVcpuState::TscRate {
                    saved_khz: 2_000_000,
                    host_khz: 3_000_000,
                    tolerance_ppm: 250,
                }
            ))),
            (
                RestoreSite::KvmSetTscKhz,
                RestoreKind::Incompatible,
                None,
                None
            )
        );
        let msr = |refusal| {
            classified(vcpu_state(HypervisorCpuError::RestoreMsr {
                index: 0x10,
                refusal,
            }))
            .1
        };
        assert_eq!(msr(MsrRefusal::NotListed), RestoreKind::Incompatible);
        assert_eq!(msr(MsrRefusal::FeatureValue), RestoreKind::Incompatible);
        assert_eq!(
            msr(MsrRefusal::Value(MsrValueCheck::Host)),
            RestoreKind::Incompatible
        );
        assert_eq!(
            msr(MsrRefusal::Value(MsrValueCheck::Content)),
            RestoreKind::Snapshot
        );
        assert_eq!(
            msr(MsrRefusal::Value(MsrValueCheck::Unattributable)),
            RestoreKind::Ambiguous
        );
        assert_eq!(
            msr(MsrRefusal::Value(MsrValueCheck::Unexamined)),
            RestoreKind::Ambiguous
        );
        // KVM refuses every Hyper-V MSR when it can't allocate the vCPU's
        // Hyper-V context, so a refused one can't be the snapshot's.
        assert_eq!(
            msr(MsrRefusal::Value(MsrValueCheck::of(0x40000021))),
            RestoreKind::Ambiguous
        );
        // A refused HWCR value is this host's kernel taking fewer bits than
        // the capture's did.
        assert_eq!(
            msr(MsrRefusal::Value(MsrValueCheck::of(MSR_K7_HWCR))),
            RestoreKind::Incompatible
        );
    }

    #[test]
    fn test_memory_restore_failures_are_classified_through_the_uffd_error() {
        let uffd = |error| {
            classified(VmError::MemoryManager(MemoryManagerError::Restore(
                MigratableError::OnDemandRestore(error),
            )))
        };
        assert_eq!(
            uffd(UffdError::Create(os_error(libc::EMFILE))),
            (
                RestoreSite::UffdCreate,
                RestoreKind::Node,
                Some(libc::EMFILE),
                None
            )
        );
        assert_eq!(
            uffd(UffdError::ConnectFaultSocket(os_error(libc::ECONNREFUSED))),
            (
                RestoreSite::PageServerConnect,
                RestoreKind::Ambiguous,
                Some(libc::ECONNREFUSED),
                None
            )
        );
        assert_eq!(uffd(UffdError::UnalignedRanges).1, RestoreKind::Snapshot);
    }

    #[test]
    fn test_vm_creation_and_device_failures_are_classified() {
        assert_eq!(
            classified(VmError::CreateHypervisorVm(HypervisorError::KvmIoctl {
                ioctl: KvmIoctl::CreateVm,
                source: errno::Error::new(libc::ENOMEM),
            })),
            (
                RestoreSite::KvmCreateVm,
                RestoreKind::Node,
                Some(libc::ENOMEM),
                Some(KvmIoctl::CreateVm)
            )
        );
        assert_eq!(
            classified(VmError::HypervisorExtensions(
                HypervisorError::CheckExtensions(anyhow!("missing"))
            ))
            .1,
            RestoreKind::Incompatible
        );
        assert_eq!(
            classified(VmError::DeviceManager(DeviceManagerError::RestoreGetState(
                MigratableError::Restore(anyhow!("bad state"))
            ))),
            (RestoreSite::DeviceState, RestoreKind::Snapshot, None, None)
        );
        assert_eq!(
            classified(VmError::DeviceManager(DeviceManagerError::EventFd(
                os_error(libc::EMFILE)
            ))),
            (
                RestoreSite::DeviceCreate,
                RestoreKind::Node,
                Some(libc::EMFILE),
                None
            )
        );
        assert_eq!(
            classified(VmError::VmAlreadyCreated),
            (RestoreSite::VmExists, RestoreKind::Request, None, None)
        );
    }

    #[test]
    fn test_an_errno_behind_an_anyhow_error_is_found() {
        assert_eq!(
            classified(VmError::Resume(MigratableError::Resume(
                anyhow::Error::new(HypervisorVmError::KvmIoctl {
                    ioctl: KvmIoctl::SetClock,
                    source: errno::Error::new(libc::EINVAL),
                })
            ))),
            (
                RestoreSite::Resume,
                RestoreKind::Ambiguous,
                Some(libc::EINVAL),
                Some(KvmIoctl::SetClock)
            )
        );
    }

    #[test]
    fn test_a_failure_reads_as_the_error_it_classifies() {
        let error =
            || VmError::MemoryManager(MemoryManagerError::SnapshotOpen(os_error(libc::ENOENT)));
        let failure = RestoreFailure::of_vm_error(error());
        assert_eq!(failure.to_string(), error().to_string());
        assert_eq!(
            failure.source().map(ToString::to_string),
            error().source().map(ToString::to_string)
        );
    }

    #[test]
    fn test_response_headers_carry_the_classification() {
        let failure = RestoreFailure::of_vm_error(vcpu_state(HypervisorCpuError::SetVcpuState {
            ioctl: KvmIoctl::SetXcrs,
            source: errno::Error::new(libc::EINVAL),
        }));
        assert_eq!(
            failure.response_headers(),
            HashMap::from([
                ("Restore-Kind".to_owned(), "ambiguous".to_owned()),
                ("Restore-Site".to_owned(), "kvm-set-xcrs".to_owned()),
                ("Restore-Errno".to_owned(), "22".to_owned()),
                ("Restore-Ioctl".to_owned(), "KVM_SET_XCRS".to_owned()),
            ])
        );
        let failure = RestoreFailure::of_vm_error(VmError::HoldClockUnpaired);
        assert_eq!(
            failure.response_headers(),
            HashMap::from([
                ("Restore-Kind".to_owned(), "incompatible".to_owned()),
                ("Restore-Site".to_owned(), "held-clock-unpaired".to_owned()),
            ])
        );
    }
}
