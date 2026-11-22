// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Names for the KVM ioctls whose failures are reported with their errno.

use std::fmt;

/// A KVM ioctl, named as the kernel's API documentation names it.
///
/// Errors carry it beside the errno the kernel returned, so a caller can
/// tell which call failed and why without reading either out of a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvmIoctl {
    /// `KVM_SET_CPUID2`.
    SetCpuid2,
    /// `KVM_SET_MP_STATE`.
    SetMpState,
    /// `KVM_SET_REGS`.
    SetRegs,
    /// `KVM_SET_SREGS`.
    SetSregs,
    /// `KVM_SET_XSAVE`.
    SetXsave,
    /// `KVM_SET_XCRS`.
    SetXcrs,
    /// `KVM_SET_LAPIC`.
    SetLapic,
    /// `KVM_SET_FPU`.
    SetFpu,
    /// `KVM_SET_TSC_KHZ`.
    SetTscKhz,
    /// `KVM_ENABLE_CAP`.
    EnableCap,
    /// `KVM_SET_MSRS`.
    SetMsrs,
    /// `KVM_SET_NESTED_STATE`.
    SetNestedState,
    /// `KVM_SET_ONE_REG`.
    SetOneReg,
    /// `KVM_SET_VCPU_EVENTS`.
    SetVcpuEvents,
}

impl KvmIoctl {
    /// The ioctl's name, as the kernel spells it.
    pub fn name(self) -> &'static str {
        match self {
            KvmIoctl::SetCpuid2 => "KVM_SET_CPUID2",
            KvmIoctl::SetMpState => "KVM_SET_MP_STATE",
            KvmIoctl::SetRegs => "KVM_SET_REGS",
            KvmIoctl::SetSregs => "KVM_SET_SREGS",
            KvmIoctl::SetXsave => "KVM_SET_XSAVE",
            KvmIoctl::SetXcrs => "KVM_SET_XCRS",
            KvmIoctl::SetLapic => "KVM_SET_LAPIC",
            KvmIoctl::SetFpu => "KVM_SET_FPU",
            KvmIoctl::SetTscKhz => "KVM_SET_TSC_KHZ",
            KvmIoctl::EnableCap => "KVM_ENABLE_CAP",
            KvmIoctl::SetMsrs => "KVM_SET_MSRS",
            KvmIoctl::SetNestedState => "KVM_SET_NESTED_STATE",
            KvmIoctl::SetOneReg => "KVM_SET_ONE_REG",
            KvmIoctl::SetVcpuEvents => "KVM_SET_VCPU_EVENTS",
        }
    }
}

impl fmt::Display for KvmIoctl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
