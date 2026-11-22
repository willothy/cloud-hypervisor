// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

use core::fmt;
use std::mem;
use std::os::raw;

use thiserror::Error;

use crate::CpuVendor;

#[cfg(all(feature = "mshv_emulator", target_arch = "x86_64"))]
pub mod emulator;
pub mod gdt;
#[expect(non_upper_case_globals)]
pub mod msr_index;

// MTRR constants
pub const MTRR_ENABLE: u64 = 0x800; // IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
pub const MTRR_MEM_TYPE_WB: u64 = 0x6;
pub const MTRR_MSR_INDICES: [u32; 28] = [
    msr_index::MSR_MTRRdefType,
    msr_index::MSR_IA32_MTRR_PHYSBASE0,
    msr_index::MSR_IA32_MTRR_PHYSMASK0,
    msr_index::MSR_IA32_MTRR_PHYSBASE1,
    msr_index::MSR_IA32_MTRR_PHYSMASK1,
    msr_index::MSR_IA32_MTRR_PHYSBASE2,
    msr_index::MSR_IA32_MTRR_PHYSMASK2,
    msr_index::MSR_IA32_MTRR_PHYSBASE3,
    msr_index::MSR_IA32_MTRR_PHYSMASK3,
    msr_index::MSR_IA32_MTRR_PHYSBASE4,
    msr_index::MSR_IA32_MTRR_PHYSMASK4,
    msr_index::MSR_IA32_MTRR_PHYSBASE5,
    msr_index::MSR_IA32_MTRR_PHYSMASK5,
    msr_index::MSR_IA32_MTRR_PHYSBASE6,
    msr_index::MSR_IA32_MTRR_PHYSMASK6,
    msr_index::MSR_IA32_MTRR_PHYSBASE7,
    msr_index::MSR_IA32_MTRR_PHYSMASK7,
    msr_index::MSR_MTRRfix64K_00000,
    msr_index::MSR_MTRRfix16K_80000,
    msr_index::MSR_MTRRfix16K_A0000,
    msr_index::MSR_MTRRfix4K_C0000,
    msr_index::MSR_MTRRfix4K_C8000,
    msr_index::MSR_MTRRfix4K_D0000,
    msr_index::MSR_MTRRfix4K_D8000,
    msr_index::MSR_MTRRfix4K_E0000,
    msr_index::MSR_MTRRfix4K_E8000,
    msr_index::MSR_MTRRfix4K_F0000,
    msr_index::MSR_MTRRfix4K_F8000,
];

// IOAPIC pins
pub const NUM_IOAPIC_PINS: usize = 24;

// X86 Exceptions
#[derive(Clone, Debug)]
pub enum Exception {
    DE = 0,  // Divide Error
    DB = 1,  // Debug Exception
    BP = 3,  // Breakpoint
    OF = 4,  // Overflow
    BR = 5,  // BOUND Range Exceeded
    UD = 6,  // Invalid/Undefined Opcode
    NM = 7,  // No Math Coprocessor
    DF = 8,  // Double Fault
    TS = 10, // Invalid TSS
    NP = 11, // Segment Not Present
    SS = 12, // Stack Segment Fault
    GP = 13, // General Protection
    PF = 14, // Page Fault
    MF = 16, // Math Fault
    AC = 17, // Alignment Check
    MC = 18, // Machine Check
    XM = 19, // SIMD Floating-Point Exception
    VE = 20, // Virtualization Exception
    CP = 21, // Control Protection Exception
}

pub mod regs;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
}

impl SegmentRegister {
    pub fn segment_type(&self) -> u8 {
        self.type_
    }

    pub fn dpl(&self) -> u8 {
        self.dpl
    }

    pub fn present(&self) -> u8 {
        self.present
    }

    pub fn long(&self) -> u8 {
        self.l
    }

    pub fn avl(&self) -> u8 {
        self.avl
    }

    pub fn desc_type(&self) -> u8 {
        self.s
    }

    pub fn granularity(&self) -> u8 {
        self.g
    }

    pub fn db(&self) -> u8 {
        self.db
    }
}

// Code segment
pub const CODE_SEGMENT_TYPE: u8 = 0x8;

// Read/Write or Read/Exec segment
pub const RWRX_SEGMENT_TYPE: u8 = 0x2;

// Expand down segment
pub const EXPAND_DOWN_SEGMENT_TYPE: u8 = 0x4;

pub fn segment_type_code(t: u8) -> bool {
    t & CODE_SEGMENT_TYPE != 0
}

pub fn segment_type_ro(t: u8) -> bool {
    t & !RWRX_SEGMENT_TYPE == 0
}

pub fn segment_type_expand_down(t: u8) -> bool {
    !segment_type_code(t) && (t & EXPAND_DOWN_SEGMENT_TYPE != 0)
}
#[macro_export]
macro_rules! msr {
    ($msr:expr) => {
        MsrEntry {
            index: $msr,
            data: 0x0,
        }
    };
}
#[macro_export]
macro_rules! msr_data {
    ($msr:expr, $data:expr) => {
        MsrEntry {
            index: $msr,
            data: $data,
        }
    };
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: SegmentRegister,
    pub gdt: DescriptorTable,
    pub idt: DescriptorTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4usize],
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl fmt::Display for CpuIdEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "function = 0x{:08x} \
             index = 0x{:08x} \
             eax = 0x{:08x} \
             ebx = 0x{:08x} \
             ecx = 0x{:08x} \
             edx = 0x{:08x} \
             flags = 0x{:08x}",
            self.function, self.index, self.eax, self.ebx, self.ecx, self.edx, self.flags
        )
    }
}

pub const CPUID_FLAG_VALID_INDEX: u32 = 1;

#[derive(Default, Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FpuState {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
}

#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LapicState {
    #[serde_as(as = "[_; 1024usize]")]
    pub(crate) regs: [raw::c_char; 1024usize],
}

impl Default for LapicState {
    fn default() -> Self {
        // SAFETY: this is plain old data structure
        unsafe { mem::zeroed() }
    }
}

impl LapicState {
    pub fn get_klapic_reg(&self, reg_offset: usize) -> u32 {
        use std::io::Cursor;
        use std::mem;

        use byteorder::{LittleEndian, ReadBytesExt};

        // SAFETY: plain old data type
        let sliceu8 = unsafe {
            // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
            // Cursors are only readable on arrays of u8, not i8(c_char).
            mem::transmute::<&[i8], &[u8]>(&self.regs[reg_offset..])
        };

        let mut reader = Cursor::new(sliceu8);
        // Following call can't fail if the offsets defined above are correct.
        reader
            .read_u32::<LittleEndian>()
            .expect("Failed to read klapic register")
    }

    pub fn set_klapic_reg(&mut self, reg_offset: usize, value: u32) {
        use std::io::Cursor;
        use std::mem;

        use byteorder::{LittleEndian, WriteBytesExt};

        // SAFETY: plain old data type
        let sliceu8 = unsafe {
            // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
            // Cursors are only readable on arrays of u8, not i8(c_char).
            mem::transmute::<&mut [i8], &mut [u8]>(&mut self.regs[reg_offset..])
        };

        let mut writer = Cursor::new(sliceu8);
        // Following call can't fail if the offsets defined above are correct.
        writer
            .write_u32::<LittleEndian>(value)
            .expect("Failed to write klapic register");
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MsrEntry {
    pub index: u32,
    pub data: u64,
}

/// What an MSR holds, as far as restoring a vCPU without it goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsrClass {
    /// A performance-monitoring counter, event select, or counter control
    /// or status register: what it holds is a count of events the guest
    /// observed, not state the guest's execution depends on.
    PerformanceMonitoring,
    /// A machine-check capability, control, status or bank register: what
    /// it holds is the record of hardware errors reported to the guest.
    MachineCheck,
    /// A register reporting a fact about the host to the guest, which the
    /// guest reads and never configures: the microcode revision, which a
    /// host's microcode update changes, and the count of SMIs taken.
    Informational,
    /// Any other MSR, which holds state the guest executes with, such as
    /// its system-call entry points, memory types, timers, paravirtual
    /// clock or speculation controls.
    Architectural,
}

impl MsrClass {
    /// The class of the MSR at `index`.
    ///
    /// The ranges cover every counter KVM can expose: up to eight general
    /// purpose and four fixed counters on Intel, and the legacy four and the
    /// six extended counters on AMD, up to 32 machine-check banks, and the
    /// two informational MSRs. An MSR is architectural unless it is listed
    /// here.
    pub fn of(index: u32) -> Self {
        match index {
            // IA32_PMCx, IA32_PERFEVTSELx, the fixed counters and their
            // control, the global status, control and overflow registers,
            // the full-width IA32_A_PMCx, PEBS and the debug store area, and
            // IA32_PERF_CAPABILITIES, which describes them.
            0xc1..=0xc8
            | 0x186..=0x18d
            | 0x309..=0x30c
            | 0x38d..=0x391
            | 0x3f1..=0x3f2
            | 0x4c1..=0x4c8
            | 0x600
            | msr_index::MSR_IA32_PERF_CAPABILITIES
            // AMD's legacy and extended performance counters and selects,
            // and the PerfMonV2 global registers.
            | 0xc0010000..=0xc0010007
            | 0xc0010200..=0xc001020b
            | 0xc0000300..=0xc0000303 => MsrClass::PerformanceMonitoring,
            // IA32_MCG_CAP, IA32_MCG_STATUS, IA32_MCG_CTL, IA32_MCG_EXT_CTL,
            // the banks' IA32_MCi_CTL2 and their CTL, STATUS, ADDR and MISC.
            msr_index::MSR_IA32_MCG_CAP..=msr_index::MSR_IA32_MCG_CTL
            | msr_index::MSR_IA32_MCG_EXT_CTL
            | 0x280..=0x29f
            | 0x400..=0x47f => MsrClass::MachineCheck,
            msr_index::MSR_IA32_UCODE_REV | msr_index::MSR_SMI_COUNT => MsrClass::Informational,
            _ => MsrClass::Architectural,
        }
    }
}

impl fmt::Display for MsrClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MsrClass::PerformanceMonitoring => "performance-monitoring",
            MsrClass::MachineCheck => "machine-check",
            MsrClass::Informational => "informational",
            MsrClass::Architectural => "architectural",
        })
    }
}

/// What KVM checks a saved value of an architectural MSR against when it
/// refuses to set it, and so what the refusal says about the snapshot.
///
/// Read from the `KVM_SET_MSRS` paths of Linux v6.18: `__kvm_set_msr()` and
/// `kvm_set_msr_common()` in `arch/x86/kvm/x86.c`, `vmx_set_msr()`,
/// `svm_set_msr()`, and the Hyper-V, MTRR and PMU handlers they call.
///
/// An MSR is [`MsrValueCheck::Content`] only when every way KVM refuses a
/// value of it is the value's own fault. A refusal that can't be attributed
/// leans towards the host or towards no one, never the snapshot, because a
/// snapshot's fault is the only kind that destroys anything: it deletes the
/// snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsrValueCheck {
    /// What this host's processor or kernel supports: its features, its
    /// paging levels, its kernel configuration, or the bits KVM's own
    /// emulation accepts. A value a capture held on another host can be
    /// refused here, so the refusal is the host's.
    Host,
    /// Only what the architecture, KVM's ABI or the vCPU's own saved state
    /// lets the MSR hold. No capture holds a value refused here, so the
    /// refusal is the snapshot's.
    Content,
    /// The value's own content, or a failure on this host that KVM reports
    /// the same way, such as an allocation it couldn't make, so the refusal
    /// can't be attributed.
    Unattributable,
    /// Not established from KVM's source: an MSR KVM v6.18 doesn't save or
    /// emulate, or one added since.
    Unexamined,
}

impl MsrValueCheck {
    /// What KVM checks a value of the architectural MSR at `index` against.
    pub fn of(index: u32) -> Self {
        match index {
            // IA32_FEATURE_CONTROL: the bits the kernel supports
            // (is_vmx_feature_control_msr_valid()). IA32_SMBASE: whether the
            // kernel is built with SMM. IA32_SPEC_CTRL and IA32_TSX_CTRL:
            // whether this processor takes the value. IA32_DEBUGCTL: the
            // bits this processor's features allow
            // (vmx_get_supported_debugctl()). The LBR records: whether this
            // processor's LBR format is the guest's. IA32_BNDCFGS: whether
            // this host has MPX. XFD, XFD_ERR and XSS: the state components
            // this host supports. TSC_AUX: whether this host switches it.
            // The PT trace MSRs: whether the kernel runs PT in host-guest
            // mode, and this processor's PT capabilities.
            msr_index::MSR_IA32_FEATURE_CONTROL
            | msr_index::MSR_IA32_SMBASE
            | 0x48 // IA32_SPEC_CTRL
            | 0x122 // IA32_TSX_CTRL
            | msr_index::MSR_IA32_DEBUGCTLMSR
            | msr_index::MSR_IA32_LASTBRANCHFROMIP..=msr_index::MSR_IA32_LASTINTTOIP
            | msr_index::MSR_IA32_BNDCFGS
            | 0x1c4 // IA32_XFD
            | 0x1c5 // IA32_XFD_ERR
            | msr_index::MSR_IA32_XSS
            | msr_index::MSR_TSC_AUX
            | 0x560..=0x561 // IA32_RTIT_OUTPUT_BASE, IA32_RTIT_OUTPUT_MASK_PTRS
            | msr_index::MSR_IA32_RTIT_CTL..=0x572 // IA32_RTIT_STATUS, IA32_RTIT_CR3_MATCH
            | 0x580..=msr_index::MSR_IA32_RTIT_ADDR3_B
            // MSRs holding linear addresses, which KVM checks for
            // canonicality at this host's paging levels, not the guest's
            // (is_noncanonical_address() in arch/x86/kvm/x86.h), so a value
            // canonical on a host with 5-level paging is refused on one
            // without: LSTAR, CSTAR and KERNEL_GS_BASE, and CET's U_CET,
            // S_CET, PL0-3_SSP and INTERRUPT_SSP_TABLE_ADDR, which KVM also
            // takes only when it grants the guest shadow stacks or IBT.
            | msr_index::MSR_LSTAR
            | msr_index::MSR_CSTAR
            | msr_index::MSR_KERNEL_GS_BASE
            | 0x6a0 // IA32_U_CET
            | 0x6a2 // IA32_S_CET
            | 0x6a4..=0x6a8 // IA32_PL0-3_SSP, IA32_INTERRUPT_SSP_TABLE_ADDR
            // MSR_KVM_STEAL_TIME: whether the kernel accounts scheduling
            // statistics (sched_info_on()). TSC_RATIO: whether KVM grants
            // the guest TSC scaling on this host. HWCR: the bits KVM's
            // emulation accepts, which differ between kernels.
            | 0x4b564d03 // MSR_KVM_STEAL_TIME
            | msr_index::MSR_AMD64_TSC_RATIO
            | msr_index::MSR_K7_HWCR
            // HV_X64_MSR_VP_INDEX: below the kernel's KVM_MAX_VCPUS.
            | 0x40000002 => MsrValueCheck::Host,
            // SYSENTER_CS, _ESP and _EIP, which KVM never refuses (it makes
            // the addresses canonical), STAR and SFMASK, the TSC, TSC_ADJUST
            // and TSC_DEADLINE, which KVM never refuses, PAT and the MTRRs,
            // whose memory types and reserved bits are architectural and
            // whose address bits are the guest's, MISC_ENABLE, POWER_CTL,
            // MISC_FEATURES_ENABLES, UMWAIT_CONTROL, VM_HSAVE_PA and
            // VIRT_SPEC_CTRL, whose reserved bits are fixed.
            msr_index::MSR_IA32_SYSENTER_CS..=msr_index::MSR_IA32_SYSENTER_EIP
            | msr_index::MSR_STAR
            | msr_index::MSR_SYSCALL_MASK
            | msr_index::MSR_IA32_TSC
            | msr_index::MSR_IA32_TSC_ADJUST
            | msr_index::MSR_IA32_TSC_DEADLINE
            | msr_index::MSR_IA32_CR_PAT
            | 0x200..=0x20f // IA32_MTRR_PHYSBASE0-PHYSMASK7, KVM's eight
            | 0x250 // IA32_MTRR_FIX64K_00000
            | 0x258..=0x259 // IA32_MTRR_FIX16K_80000, _A0000
            | 0x268..=0x26f // IA32_MTRR_FIX4K_C0000-F8000
            | msr_index::MSR_MTRRdefType
            | msr_index::MSR_IA32_MISC_ENABLE
            | msr_index::MSR_IA32_POWER_CTL
            | 0x140 // MSR_MISC_FEATURES_ENABLES
            | 0xe1 // IA32_UMWAIT_CONTROL
            | msr_index::MSR_VM_HSAVE_PA
            | 0xc001011f // MSR_AMD64_VIRT_SPEC_CTRL
            // KVM's paravirtual MSRs other than steal time: their reserved
            // bits are KVM's ABI, and their addresses must lie in the
            // guest's memory.
            | 0x11 // MSR_KVM_WALL_CLOCK
            | 0x12 // MSR_KVM_SYSTEM_TIME
            | 0x4b564d00..=0x4b564d02 // MSR_KVM_WALL_CLOCK_NEW, _SYSTEM_TIME_NEW, _ASYNC_PF_EN
            // MSR_KVM_PV_EOI_EN, _POLL_CONTROL, _ASYNC_PF_INT, _ASYNC_PF_ACK
            | 0x4b564d04..=0x4b564d07 => MsrValueCheck::Content,
            // The Hyper-V MSRs other than the VP index: KVM refuses values
            // the Hyper-V ABI reserves, addresses outside the guest's memory
            // and SynIC state the checked SynIC capability already covers,
            // but also every one of them when it can't allocate the vCPU's
            // Hyper-V context (kvm_hv_vcpu_init() in kvm_hv_set_msr_common()).
            0x40000000..=0x40000001 | 0x40000003..=0x400001ff => MsrValueCheck::Unattributable,
            _ => MsrValueCheck::Unexamined,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VcpuMsrConfigUpdate {
    pub feature_msrs: Vec<MsrEntry>,
    pub snapshottable_msr_indices: Vec<u32>,
}

#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XsaveState {
    #[serde_as(as = "[_; 1024usize]")]
    pub region: [u32; 1024usize],

    // extra data to support xsave2
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<u32>,
}

impl Default for XsaveState {
    fn default() -> Self {
        Self {
            // SAFETY: this is plain old data structure
            region: unsafe { mem::zeroed() },
            extra: Vec::new(),
        }
    }
}

const ARCH_GET_XCOMP_SUPP: usize = 0x1021;
const ARCH_REQ_XCOMP_GUEST_PERM: usize = 0x1025;
const ARCH_XCOMP_TILECFG: usize = 17;
const ARCH_XCOMP_TILEDATA: usize = 18;

/// Checks whether the host supports AMX.
///
/// Returns `Ok` if AMX is supported on the host and `Err` otherwise.
pub(crate) fn amx_supported(cpu_vendor: CpuVendor) -> Result<(), AmxGuestSupportError> {
    if !matches!(cpu_vendor, CpuVendor::Intel) {
        return Err(AmxGuestSupportError::VendorDoesNotSupportAmx);
    }
    // We make a syscall to get information about which dynamically enabled
    // XSAVE state components are supported. The corresponding state
    // component bits will get set in `features`
    let mut features: usize = 0;
    // SAFETY: Syscall with valid parameters
    let result =
        unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_XCOMP_SUPP, &raw mut features) };
    // Ensure that both the TILECFG and TILEDATA state components are supported
    let mask = (1 << ARCH_XCOMP_TILECFG) | (1 << ARCH_XCOMP_TILEDATA);
    if result != 0 {
        return Err(AmxGuestSupportError::AmxNotSupported { errno: result });
    }

    if (features & mask) == mask {
        Ok(())
    } else {
        Err(AmxGuestSupportError::InvalidAmxTileFeatureCheck { features })
    }
}

/// Asks the kernel to provide AMX support for guests.
pub(crate) fn request_guest_amx_support() -> Result<(), AmxGuestSupportError> {
    // Make a syscall to request permission for guests to use the TILECFG
    // and TILEDATA state components. Note that as per the kernel
    // [documentation](https://docs.kernel.org/arch/x86/xstate.html#dynamic-features-for-virtual-machines)
    // we need to pass in the number of the highest XSTATE component which is required for
    // the facility to work which in this case is TILEDATA.
    //
    // This syscall will alter the size of `kvm_xsave` when KVM is used as the hypervisor.
    //
    // SAFETY: Syscall with valid parameters
    let result = unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_REQ_XCOMP_GUEST_PERM,
            ARCH_XCOMP_TILEDATA,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        // Unwrap is OK because we verified that `result` is not zero
        Err(AmxGuestSupportError::AmxGuestTileRequest { errno: result })
    }
}

/// Error that may be returned when attempting to enable AMX state components for guests
#[derive(Debug, Error)]
pub enum AmxGuestSupportError {
    /// Attempted to enable AMX on a CPU from a vendor that is not known to support AMX features.
    #[error("The host CPU's vendor does not support AMX features. Only Intel provides such CPUs.")]
    VendorDoesNotSupportAmx,
    /// Unable to verify that the host supports AMX.
    #[error("The host does not support AMX tile state components: errno={errno}")]
    AmxNotSupported { errno: i64 },
    /// The syscall to check for AMX tile state support succeeded, but the returned
    /// features did not match our expectations.
    #[error(
        "Could not verify AMX support. These are the supported features that were reported: features={features}"
    )]
    InvalidAmxTileFeatureCheck { features: usize },
    /// The request to enable AMX related state components for guests failed.
    #[error("Failed to enable AMX tile state components for guests: errno={errno}")]
    AmxGuestTileRequest { errno: i64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msr_class_tolerates_only_counters_machine_checks_and_host_facts() {
        for index in [
            0xc1, 0xc8, 0x186, 0x18d, 0x309, 0x30c, 0x38d, 0x38f, 0x391, 0x3f1, 0x4c1, 0x600,
            0xc0010000, 0xc0010007, 0xc0010200, 0xc001020b, 0xc0000300, 0xc0000303,
        ] {
            assert_eq!(
                MsrClass::of(index),
                MsrClass::PerformanceMonitoring,
                "{index:#x}"
            );
        }
        assert_eq!(
            MsrClass::of(msr_index::MSR_IA32_PERF_CAPABILITIES),
            MsrClass::PerformanceMonitoring
        );
        for index in [0x179, 0x17a, 0x17b, 0x4d0, 0x280, 0x29f, 0x400, 0x47f] {
            assert_eq!(MsrClass::of(index), MsrClass::MachineCheck, "{index:#x}");
        }
        for index in [msr_index::MSR_IA32_UCODE_REV, msr_index::MSR_SMI_COUNT] {
            assert_eq!(MsrClass::of(index), MsrClass::Informational, "{index:#x}");
        }
        for index in [
            msr_index::MSR_IA32_TSC,
            msr_index::MSR_IA32_SYSENTER_CS,
            msr_index::MSR_IA32_CR_PAT,
            msr_index::MSR_IA32_MISC_ENABLE,
            msr_index::MSR_IA32_TSC_DEADLINE,
            msr_index::MSR_EFER,
            msr_index::MSR_LSTAR,
            msr_index::MSR_KERNEL_GS_BASE,
            msr_index::MSR_TSC_AUX,
            msr_index::MSR_MTRRdefType,
            0x48,       // IA32_SPEC_CTRL
            0x1d9,      // IA32_DEBUGCTL
            0x4b564d01, // MSR_KVM_SYSTEM_TIME_NEW
            0xc0010008, // past the legacy AMD counters
            0x480,      // past the last machine-check bank
            msr_index::MSR_K7_HWCR,
        ] {
            assert_eq!(MsrClass::of(index), MsrClass::Architectural, "{index:#x}");
        }
    }

    #[test]
    fn test_msr_value_check_tells_host_limits_from_invalid_content() {
        // KVM's emulation accepts only bits 18 and 24 of HWCR, which differ
        // between kernels, and IA32_SPEC_CTRL takes what this processor
        // takes.
        assert_eq!(
            MsrValueCheck::of(msr_index::MSR_K7_HWCR),
            MsrValueCheck::Host
        );
        assert_eq!(MsrValueCheck::of(0x48), MsrValueCheck::Host);
        // PAT's memory types are architectural.
        assert_eq!(
            MsrValueCheck::of(msr_index::MSR_IA32_CR_PAT),
            MsrValueCheck::Content
        );
        // KVM refuses a Hyper-V MSR the same way whether its value is
        // reserved or KVM couldn't allocate the vCPU's Hyper-V context.
        assert_eq!(
            MsrValueCheck::of(0x40000021), // HV_X64_MSR_REFERENCE_TSC
            MsrValueCheck::Unattributable
        );
        // VM_CR isn't among the MSRs KVM v6.18 saves or emulates.
        assert_eq!(MsrValueCheck::of(0xc0010114), MsrValueCheck::Unexamined);
    }
}
