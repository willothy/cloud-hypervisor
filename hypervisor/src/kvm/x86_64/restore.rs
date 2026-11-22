// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Checks of a saved vCPU state against what the host can present, made
//! before any of the state is set.
//!
//! KVM refuses a state the host can't present with the same EINVAL it
//! returns for state it rejects for what it holds. Comparing the state with
//! the host's capabilities first tells the two apart: a component these
//! checks pass that KVM still refuses is refused for its content, or for a
//! reason the kernel doesn't report.

use kvm_bindings::nested::KvmNestedStateBuffer;
use kvm_bindings::{
    KVM_STATE_NESTED_FORMAT_SVM, KVM_STATE_NESTED_FORMAT_VMX, KVM_VCPUEVENT_VALID_NMI_PENDING,
    KVM_VCPUEVENT_VALID_SHADOW, KVM_VCPUEVENT_VALID_SIPI_VECTOR, KVM_VCPUEVENT_VALID_SMM,
};

use crate::arch::x86::{CpuIdEntry, XsaveState};
use crate::cpu::IncompatibleVcpuState;
use crate::kvm::x86_64::{ExtendedControlRegisters, VcpuEvents};

const CR4_UMIP: u64 = 1 << 11;
const CR4_LA57: u64 = 1 << 12;
const CR4_VMXE: u64 = 1 << 13;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_PCIDE: u64 = 1 << 17;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const CR4_PKE: u64 = 1 << 22;
const CR4_CET: u64 = 1 << 23;
const CR4_LAM_SUP: u64 = 1 << 28;

/// The CR4 bits KVM lets a guest set at all: `CR4_RESERVED_BITS` in the
/// kernel's `arch/x86/include/asm/kvm_host.h` is its complement. VME, PVI,
/// TSD, DE, PSE, PAE, MCE, PGE, PCE, OSFXSR and OSXMMEXCPT are bits 0 to 10.
const CR4_KVM_BITS: u64 = 0x7ff
    | CR4_UMIP
    | CR4_LA57
    | CR4_VMXE
    | CR4_FSGSBASE
    | CR4_PCIDE
    | CR4_OSXSAVE
    | CR4_SMEP
    | CR4_SMAP
    | CR4_PKE
    | CR4_CET
    | CR4_LAM_SUP;

/// The x87 and SSE state components, which every XSAVE area may hold.
const XFEATURE_MASK_FPSSE: u64 = 0b11;
/// The x87 state component, which XCR0 may always enable.
const XFEATURE_MASK_FP: u64 = 0b1;

/// The index of XCR0 among the extended control registers.
const XCR_XFEATURE_ENABLED_MASK: u32 = 0;

/// The vCPU event flags KVM accepts on a VM that enables neither exception
/// payloads (`KVM_CAP_EXCEPTION_PAYLOAD`) nor triple-fault events
/// (`KVM_CAP_X86_TRIPLE_FAULT_EVENT`), which this VMM never does.
const VCPU_EVENTS_FLAGS: u32 = KVM_VCPUEVENT_VALID_NMI_PENDING
    | KVM_VCPUEVENT_VALID_SIPI_VECTOR
    | KVM_VCPUEVENT_VALID_SHADOW
    | KVM_VCPUEVENT_VALID_SMM;

/// A CPUID output register.
#[derive(Clone, Copy)]
enum Register {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

/// A feature bit of the host's supported CPUID.
#[derive(Clone, Copy)]
struct Feature {
    function: u32,
    index: u32,
    register: Register,
    bit: u32,
}

impl Feature {
    const VMX: Feature = Feature::new(1, 0, Register::Ecx, 5);
    const PCID: Feature = Feature::new(1, 0, Register::Ecx, 17);
    const XSAVE: Feature = Feature::new(1, 0, Register::Ecx, 26);
    const FSGSBASE: Feature = Feature::new(7, 0, Register::Ebx, 0);
    const SMEP: Feature = Feature::new(7, 0, Register::Ebx, 7);
    const SMAP: Feature = Feature::new(7, 0, Register::Ebx, 20);
    const UMIP: Feature = Feature::new(7, 0, Register::Ecx, 2);
    const PKU: Feature = Feature::new(7, 0, Register::Ecx, 3);
    const SHSTK: Feature = Feature::new(7, 0, Register::Ecx, 7);
    const LA57: Feature = Feature::new(7, 0, Register::Ecx, 16);
    const IBT: Feature = Feature::new(7, 0, Register::Edx, 20);
    const LAM: Feature = Feature::new(7, 1, Register::Eax, 26);
    const SVM: Feature = Feature::new(0x8000_0001, 0, Register::Ecx, 2);

    const fn new(function: u32, index: u32, register: Register, bit: u32) -> Self {
        Feature {
            function,
            index,
            register,
            bit,
        }
    }
}

/// What the host can present to a guest's vCPU, as KVM reports it.
pub(crate) struct HostVcpuCapabilities {
    /// What `KVM_GET_SUPPORTED_CPUID` reports.
    pub(crate) supported_cpuid: Vec<CpuIdEntry>,
    /// The TSC rate, in kHz, of a vCPU no rate has been set on: the rate
    /// KVM runs a guest's TSC at unscaled.
    pub(crate) tsc_khz: u32,
    /// Whether KVM can scale a guest's TSC to another rate
    /// (`KVM_CAP_TSC_CONTROL`).
    pub(crate) tsc_scaling: bool,
    /// Whether KVM emulates the Hyper-V synthetic interrupt controller
    /// (`KVM_CAP_HYPERV_SYNIC`).
    pub(crate) hyperv_synic: bool,
    /// Whether KVM saves and restores nested virtualization state
    /// (`KVM_CAP_NESTED_STATE`).
    pub(crate) nested_state: bool,
    /// Whether KVM supports system-management mode (`KVM_CAP_X86_SMM`).
    pub(crate) smm: bool,
}

impl HostVcpuCapabilities {
    /// Whether the host's supported CPUID has `feature`.
    fn has(&self, feature: Feature) -> bool {
        self.supported_cpuid.iter().any(|entry| {
            let value = match feature.register {
                Register::Eax => entry.eax,
                Register::Ebx => entry.ebx,
                Register::Ecx => entry.ecx,
                Register::Edx => entry.edx,
            };
            entry.function == feature.function
                && entry.index == feature.index
                && value & (1 << feature.bit) != 0
        })
    }

    /// The XSAVE state components the host lets a guest enable: EDX:EAX of
    /// the supported CPUID's leaf 0xd, subleaf 0.
    fn supported_xcr0(&self) -> u64 {
        self.supported_cpuid
            .iter()
            .find(|entry| entry.function == 0xd && entry.index == 0)
            .map_or(0, |entry| {
                (u64::from(entry.edx) << 32) | u64::from(entry.eax)
            })
    }

    /// The CR4 bits no guest may set on this host, computed the way the
    /// kernel's `__cr4_reserved_bits()` (`arch/x86/kvm/x86.h`) computes
    /// them from KVM's capabilities.
    fn cr4_reserved_bits(&self) -> u64 {
        let mut reserved = !CR4_KVM_BITS;
        for (feature, bit) in [
            (Feature::XSAVE, CR4_OSXSAVE),
            (Feature::SMEP, CR4_SMEP),
            (Feature::SMAP, CR4_SMAP),
            (Feature::FSGSBASE, CR4_FSGSBASE),
            (Feature::PKU, CR4_PKE),
            (Feature::LA57, CR4_LA57),
            (Feature::UMIP, CR4_UMIP),
            (Feature::VMX, CR4_VMXE),
            (Feature::PCID, CR4_PCIDE),
            (Feature::LAM, CR4_LAM_SUP),
        ] {
            if !self.has(feature) {
                reserved |= bit;
            }
        }
        if !self.has(Feature::SHSTK) && !self.has(Feature::IBT) {
            reserved |= CR4_CET;
        }
        reserved
    }

    /// Checks that the host runs a guest TSC at `saved_khz`.
    ///
    /// A host that scales TSCs runs any rate KVM accepts. One that doesn't
    /// runs a guest's TSC at the host's rate, and KVM takes a saved rate as
    /// that one only within `tolerance_ppm` of it (`kvm_set_tsc_khz()` in
    /// `arch/x86/kvm/x86.c`): below the band it refuses the rate, and above
    /// it it emulates the rate by catching the guest's TSC up on every
    /// entry, which runs it unevenly. Both are refused here.
    ///
    /// Without the host's tolerance, which only `kvm.tsc_tolerance_ppm`
    /// gives, a rate other than the host's own can't be checked, and KVM
    /// decides alone.
    pub(crate) fn check_tsc_khz(
        &self,
        saved_khz: u32,
        tolerance_ppm: Option<u32>,
    ) -> Result<(), IncompatibleVcpuState> {
        if self.tsc_scaling || saved_khz == self.tsc_khz {
            return Ok(());
        }
        let Some(tolerance_ppm) = tolerance_ppm else {
            return Ok(());
        };
        // adjust_tsc_khz() in arch/x86/kvm/x86.c: 64-bit arithmetic,
        // truncating division.
        let host_khz = u64::from(self.tsc_khz);
        let tolerance = u64::from(tolerance_ppm);
        let low = host_khz * 1_000_000u64.saturating_sub(tolerance) / 1_000_000;
        let high = host_khz * (1_000_000 + tolerance) / 1_000_000;
        if (low..=high).contains(&u64::from(saved_khz)) {
            return Ok(());
        }
        Err(IncompatibleVcpuState::TscRate {
            saved_khz,
            host_khz: self.tsc_khz,
            tolerance_ppm,
        })
    }

    /// Checks that the host lets a guest set every bit of `cr4`.
    pub(crate) fn check_cr4(&self, cr4: u64) -> Result<(), IncompatibleVcpuState> {
        match cr4 & self.cr4_reserved_bits() {
            0 => Ok(()),
            bits => Err(IncompatibleVcpuState::Cr4 { bits }),
        }
    }

    /// Checks that the host supports every state component `xsave` holds,
    /// which KVM_SET_XSAVE checks (`validate_user_xstate_header()` in
    /// `arch/x86/kernel/fpu/xstate.c`) against the components the guest's
    /// CPUID permits of those the host supports.
    pub(crate) fn check_xsave(&self, xsave: &XsaveState) -> Result<(), IncompatibleVcpuState> {
        // XSTATE_BV, the first field of the XSAVE header at byte 512.
        let components = (u64::from(xsave.region[129]) << 32) | u64::from(xsave.region[128]);
        match components & !(self.supported_xcr0() | XFEATURE_MASK_FPSSE) {
            0 => Ok(()),
            components => Err(IncompatibleVcpuState::XsaveComponents { components }),
        }
    }

    /// Checks that the host supports every state component XCR0 in `xcrs`
    /// enables, which `__kvm_set_xcr()` (`arch/x86/kvm/x86.c`) checks
    /// against the components the guest's CPUID permits of those the host
    /// supports.
    pub(crate) fn check_xcrs(
        &self,
        xcrs: &ExtendedControlRegisters,
    ) -> Result<(), IncompatibleVcpuState> {
        let Some(xcr0) = xcrs
            .xcrs
            .iter()
            .take(xcrs.nr_xcrs as usize)
            .find(|xcr| xcr.xcr == XCR_XFEATURE_ENABLED_MASK)
        else {
            return Ok(());
        };
        match xcr0.value & !(self.supported_xcr0() | XFEATURE_MASK_FP) {
            0 => Ok(()),
            components => Err(IncompatibleVcpuState::Xcr0 { components }),
        }
    }

    /// Checks that the host emulates the Hyper-V synthetic interrupt
    /// controller a state enabling it needs.
    pub(crate) fn check_hyperv_synic(&self) -> Result<(), IncompatibleVcpuState> {
        if self.hyperv_synic {
            Ok(())
        } else {
            Err(IncompatibleVcpuState::HypervSynic)
        }
    }

    /// Checks that the host restores nested state in `nested`'s format: KVM
    /// restores it only with nested virtualization enabled, and only in the
    /// format of the host's own virtualization extension, which the
    /// supported CPUID then reports.
    pub(crate) fn check_nested_state(
        &self,
        nested: &KvmNestedStateBuffer,
    ) -> Result<(), IncompatibleVcpuState> {
        let supported = self.nested_state
            && match u32::from(nested.format) {
                KVM_STATE_NESTED_FORMAT_VMX => self.has(Feature::VMX),
                KVM_STATE_NESTED_FORMAT_SVM => self.has(Feature::SVM),
                _ => false,
            };
        if supported {
            Ok(())
        } else {
            Err(IncompatibleVcpuState::NestedState {
                format: nested.format,
            })
        }
    }

    /// Checks that the host supports the CET shadow stacks a saved shadow
    /// stack pointer belongs to.
    pub(crate) fn check_shadow_stack(&self) -> Result<(), IncompatibleVcpuState> {
        if self.has(Feature::SHSTK) {
            Ok(())
        } else {
            Err(IncompatibleVcpuState::ShadowStack)
        }
    }

    /// Checks that KVM accepts `events` on this VM, the way
    /// `kvm_vcpu_ioctl_x86_set_vcpu_events()` (`arch/x86/kvm/x86.c`) does:
    /// it refuses a flag for a capability the VM didn't enable, and
    /// system-management state on a kernel without SMM.
    pub(crate) fn check_vcpu_events(
        &self,
        events: &VcpuEvents,
    ) -> Result<(), IncompatibleVcpuState> {
        let flags = events.flags & !VCPU_EVENTS_FLAGS;
        if flags != 0 {
            return Err(IncompatibleVcpuState::VcpuEvents { flags });
        }
        let in_smm = events.flags & KVM_VCPUEVENT_VALID_SMM != 0
            && (events.smi.smm != 0 || events.smi.pending != 0 || events.smi.smm_inside_nmi != 0);
        if in_smm && !self.smm {
            return Err(IncompatibleVcpuState::Smm);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kvm_bindings::{KVM_VCPUEVENT_VALID_PAYLOAD, KVM_VCPUEVENT_VALID_TRIPLE_FAULT, kvm_xcr};

    use super::*;

    /// A host with every feature the checks look at, scaling TSCs at
    /// 3 GHz, and supporting x87, SSE and AVX state.
    fn host() -> HostVcpuCapabilities {
        HostVcpuCapabilities {
            supported_cpuid: vec![
                CpuIdEntry {
                    function: 1,
                    ecx: (1 << 5) | (1 << 17) | (1 << 26),
                    ..Default::default()
                },
                CpuIdEntry {
                    function: 7,
                    ebx: 1 | (1 << 7) | (1 << 20),
                    ecx: (1 << 2) | (1 << 3) | (1 << 7) | (1 << 16),
                    edx: 1 << 20,
                    ..Default::default()
                },
                CpuIdEntry {
                    function: 7,
                    index: 1,
                    eax: 1 << 26,
                    ..Default::default()
                },
                CpuIdEntry {
                    function: 0xd,
                    eax: 0b111,
                    ..Default::default()
                },
                CpuIdEntry {
                    function: 0x8000_0001,
                    ecx: 1 << 2,
                    ..Default::default()
                },
            ],
            tsc_khz: 3_000_000,
            tsc_scaling: true,
            hyperv_synic: true,
            nested_state: true,
            smm: true,
        }
    }

    /// A host at the same rate with none of the optional features, which
    /// supports only x87 and SSE state.
    fn bare_host() -> HostVcpuCapabilities {
        HostVcpuCapabilities {
            supported_cpuid: vec![CpuIdEntry {
                function: 0xd,
                eax: 0b11,
                ..Default::default()
            }],
            tsc_khz: 3_000_000,
            tsc_scaling: false,
            hyperv_synic: false,
            nested_state: false,
            smm: false,
        }
    }

    #[test]
    fn test_tsc_rate_restores_unscaled_within_the_tolerance_band() {
        let host = bare_host();
        // 250 ppm of 3 GHz is 750 kHz either side.
        for saved_khz in [3_000_000, 2_999_250, 3_000_750] {
            assert_eq!(host.check_tsc_khz(saved_khz, Some(250)), Ok(()));
        }
        for saved_khz in [2_999_249, 3_000_751] {
            assert_eq!(
                host.check_tsc_khz(saved_khz, Some(250)),
                Err(IncompatibleVcpuState::TscRate {
                    saved_khz,
                    host_khz: 3_000_000,
                    tolerance_ppm: 250,
                })
            );
        }
    }

    #[test]
    fn test_tsc_rate_is_left_to_kvm_with_scaling_or_without_a_tolerance() {
        assert_eq!(host().check_tsc_khz(1_000_000, Some(250)), Ok(()));
        assert_eq!(bare_host().check_tsc_khz(1_000_000, None), Ok(()));
    }

    #[test]
    fn test_cr4_bits_need_the_feature_behind_them() {
        let feature_bits = CR4_OSXSAVE
            | CR4_SMEP
            | CR4_SMAP
            | CR4_FSGSBASE
            | CR4_PKE
            | CR4_LA57
            | CR4_UMIP
            | CR4_VMXE
            | CR4_PCIDE
            | CR4_LAM_SUP
            | CR4_CET;
        assert_eq!(host().check_cr4(0x7ff | feature_bits), Ok(()));
        assert_eq!(bare_host().check_cr4(0x7ff), Ok(()));
        assert_eq!(
            bare_host().check_cr4(0x7ff | feature_bits),
            Err(IncompatibleVcpuState::Cr4 { bits: feature_bits })
        );
        // SMXE is never KVM's to set.
        assert_eq!(
            host().check_cr4(1 << 14),
            Err(IncompatibleVcpuState::Cr4 { bits: 1 << 14 })
        );
    }

    #[test]
    fn test_cet_in_cr4_needs_shadow_stacks_or_indirect_branch_tracking() {
        let mut host = host();
        host.supported_cpuid[1].ecx &= !(1 << 7);
        assert_eq!(host.check_cr4(CR4_CET), Ok(()));
        host.supported_cpuid[1].edx = 0;
        assert_eq!(
            host.check_cr4(CR4_CET),
            Err(IncompatibleVcpuState::Cr4 { bits: CR4_CET })
        );
    }

    #[test]
    fn test_xsave_components_need_host_support() {
        let mut xsave = XsaveState::default();
        xsave.region[128] = 0b111;
        assert_eq!(host().check_xsave(&xsave), Ok(()));
        assert_eq!(
            bare_host().check_xsave(&xsave),
            Err(IncompatibleVcpuState::XsaveComponents { components: 0b100 })
        );
        xsave.region[128] = 0b11;
        xsave.region[129] = 1 << 1;
        assert_eq!(
            host().check_xsave(&xsave),
            Err(IncompatibleVcpuState::XsaveComponents {
                components: 1 << 33
            })
        );
    }

    #[test]
    fn test_xcr0_components_need_host_support() {
        let mut xcrs = ExtendedControlRegisters {
            nr_xcrs: 1,
            ..Default::default()
        };
        xcrs.xcrs[0] = kvm_xcr {
            xcr: XCR_XFEATURE_ENABLED_MASK,
            reserved: 0,
            value: 0b111,
        };
        assert_eq!(host().check_xcrs(&xcrs), Ok(()));
        assert_eq!(
            bare_host().check_xcrs(&xcrs),
            Err(IncompatibleVcpuState::Xcr0 { components: 0b100 })
        );
        // An entry past nr_xcrs isn't one KVM reads.
        xcrs.nr_xcrs = 0;
        assert_eq!(bare_host().check_xcrs(&xcrs), Ok(()));
    }

    #[test]
    fn test_nested_state_needs_the_hosts_own_format() {
        let mut nested = KvmNestedStateBuffer::empty();
        nested.format = KVM_STATE_NESTED_FORMAT_VMX as u16;
        assert_eq!(host().check_nested_state(&nested), Ok(()));
        let mut amd = host();
        amd.supported_cpuid[0].ecx &= !(1 << 5);
        assert_eq!(
            amd.check_nested_state(&nested),
            Err(IncompatibleVcpuState::NestedState { format: 0 })
        );
        nested.format = KVM_STATE_NESTED_FORMAT_SVM as u16;
        assert_eq!(amd.check_nested_state(&nested), Ok(()));
        assert_eq!(
            bare_host().check_nested_state(&nested),
            Err(IncompatibleVcpuState::NestedState { format: 1 })
        );
    }

    #[test]
    fn test_synic_and_shadow_stacks_need_host_support() {
        assert_eq!(host().check_hyperv_synic(), Ok(()));
        assert_eq!(
            bare_host().check_hyperv_synic(),
            Err(IncompatibleVcpuState::HypervSynic)
        );
        assert_eq!(host().check_shadow_stack(), Ok(()));
        assert_eq!(
            bare_host().check_shadow_stack(),
            Err(IncompatibleVcpuState::ShadowStack)
        );
    }

    #[test]
    fn test_vcpu_events_need_flags_this_vm_enables() {
        let mut events = VcpuEvents {
            flags: VCPU_EVENTS_FLAGS,
            ..Default::default()
        };
        assert_eq!(bare_host().check_vcpu_events(&events), Ok(()));
        events.flags |= KVM_VCPUEVENT_VALID_PAYLOAD | KVM_VCPUEVENT_VALID_TRIPLE_FAULT;
        assert_eq!(
            host().check_vcpu_events(&events),
            Err(IncompatibleVcpuState::VcpuEvents {
                flags: KVM_VCPUEVENT_VALID_PAYLOAD | KVM_VCPUEVENT_VALID_TRIPLE_FAULT
            })
        );
        events.flags = VCPU_EVENTS_FLAGS;
        events.smi.pending = 1;
        assert_eq!(host().check_vcpu_events(&events), Ok(()));
        assert_eq!(
            bare_host().check_vcpu_events(&events),
            Err(IncompatibleVcpuState::Smm)
        );
        events.flags &= !KVM_VCPUEVENT_VALID_SMM;
        assert_eq!(bare_host().check_vcpu_events(&events), Ok(()));
    }
}
