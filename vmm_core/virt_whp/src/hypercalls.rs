// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Hv1State;
use crate::WhpProcessor;
use crate::memory::VtlAccess;
use crate::vsm;
use crate::vtl2;
#[cfg(guest_arch = "aarch64")]
use aarch64 as arch;
use hv1_hypercall::HvRepResult;
use hvdef::HV_PAGE_SIZE;
use hvdef::HV_PARTITION_ID_SELF;
use hvdef::HV_VP_INDEX_SELF;
use hvdef::HvError;
use hvdef::HvMapGpaFlags;
use hvdef::Vtl;
use hvdef::hypercall::HostVisibilityType;
use hvdef::hypercall::HvInterceptType;
use hvdef::hypercall::VbsVmCallReportOutput;
use memory_range::MemoryRange;
use std::iter::zip;
use std::ops::RangeInclusive;
use virt::PageVisibility;
use virt::VpIndex;
#[cfg(guest_arch = "x86_64")]
use x86 as arch;

pub(crate) struct WhpHypercallExit<'a, 'b> {
    vp: &'a mut WhpProcessor<'b>,
    registers: arch::WhpHypercallRegisters<'a>,
}

#[derive(Debug, Copy, Clone)]
enum RegisterTarget {
    Current,
    Vtl(Vtl),
}

impl RegisterTarget {
    fn from_option(vtl: Option<Vtl>) -> Self {
        match vtl {
            Some(vtl) => Self::Vtl(vtl),
            None => Self::Current,
        }
    }

    fn explicit(self) -> Option<Vtl> {
        match self {
            Self::Current => None,
            Self::Vtl(vtl) => Some(vtl),
        }
    }

    fn resolve_for_emulation(self, active_vtl: Vtl) -> Vtl {
        match self {
            Self::Current => active_vtl,
            Self::Vtl(vtl) => vtl,
        }
    }
}

fn whp_vsm_error_to_hv_error(err: &vsm::VsmError) -> HvError {
    match err {
        vsm::VsmError::InvalidVpIndex(_) => HvError::InvalidVpIndex,
        vsm::VsmError::VsmDisabled => HvError::AccessDenied,
        vsm::VsmError::VtlNotEnabled { .. }
        | vsm::VsmError::InvalidTargetVtl0
        | vsm::VsmError::VpVtlNotEnabled { .. }
        | vsm::VsmError::InvalidRegisterVtl { .. }
        | vsm::VsmError::UnsupportedMapFlags { .. }
        | vsm::VsmError::UnsupportedHostVisibility { .. }
        | vsm::VsmError::GpaPageOverflow { .. } => HvError::InvalidParameter,
        vsm::VsmError::InvalidRegisterValue => HvError::InvalidRegisterValue,
        vsm::VsmError::VpVtlAlreadyEnabled { .. } => HvError::VtlAlreadyEnabled,
        vsm::VsmError::WhpTimeout(_) => HvError::Timeout,
        vsm::VsmError::GuestVsmHostSupportRequired(_) => HvError::UnknownRegisterName,
        vsm::VsmError::Vtl0Only
        | vsm::VsmError::IncompatibleWithIsolation
        | vsm::VsmError::HostUnsupported
        | vsm::VsmError::InvalidActiveVtl { .. }
        | vsm::VsmError::ShortOperation { .. }
        | vsm::VsmError::WhpOperation { .. }
        | vsm::VsmError::Whp(_) => HvError::OperationFailed,
        #[cfg(not(guest_arch = "x86_64"))]
        vsm::VsmError::UnsupportedArchitecture => HvError::OperationFailed,
    }
}

fn whp_vsm_protection_error_to_hv_result_ref(err: &vsm::VsmError) -> (HvError, usize) {
    let completed = err.completed_pages();
    let hv_error = match err {
        vsm::VsmError::WhpTimeout(_) => HvError::Timeout,
        vsm::VsmError::WhpOperation { source, .. } | vsm::VsmError::Whp(source) => {
            if source.is_timeout() {
                HvError::Timeout
            } else {
                source
                    .hv_result()
                    .map_or(HvError::OperationFailed, HvError::from)
            }
        }
        _ => whp_vsm_error_to_hv_error(err),
    };

    (hv_error, completed)
}

fn whp_vsm_protection_error_to_hv_result(err: vsm::VsmError) -> (HvError, usize) {
    let (hv_error, completed) = whp_vsm_protection_error_to_hv_result_ref(&err);
    tracing::trace!(
        error = &err as &dyn std::error::Error,
        ?hv_error,
        completed,
        "VSM protection operation rejected"
    );
    (hv_error, completed)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct WhpVsmProtectionPageSummary {
    first_gpfn: Option<u64>,
    last_gpfn: Option<u64>,
    min_gpfn: Option<u64>,
    max_gpfn: Option<u64>,
    contiguous: bool,
    first_gpa: Option<u64>,
    last_gpa: Option<u64>,
}

fn whp_vsm_protection_page_summary(gpa_pages: &[u64]) -> WhpVsmProtectionPageSummary {
    WhpVsmProtectionPageSummary {
        first_gpfn: gpa_pages.first().copied(),
        last_gpfn: gpa_pages.last().copied(),
        min_gpfn: gpa_pages.iter().copied().min(),
        max_gpfn: gpa_pages.iter().copied().max(),
        contiguous: gpa_pages
            .windows(2)
            .all(|pages| pages[0].checked_add(1) == Some(pages[1])),
        first_gpa: gpa_pages
            .first()
            .and_then(|gpfn| gpfn.checked_mul(HV_PAGE_SIZE)),
        last_gpa: gpa_pages
            .last()
            .and_then(|gpfn| gpfn.checked_mul(HV_PAGE_SIZE)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn whp_vsm_register_timeout_maps_to_hv_timeout() {
        for hresult in [0x80350078_u32, 0x800705b4] {
            let timeout = whp::WHvError::from_hresult(hresult as i32).expect("nonzero HRESULT");
            assert!(timeout.is_timeout());
            assert_eq!(
                whp_vsm_error_to_hv_error(&vsm::VsmError::WhpTimeout(timeout)),
                HvError::Timeout
            );
        }
    }

    #[test]
    fn whp_vsm_protection_timeout_preserves_progress() {
        let timeout = whp::WHvError::from_hresult(0x80350078_u32 as i32).expect("nonzero HRESULT");
        let error = vsm::VsmError::WhpOperation {
            source: timeout,
            processed: 3,
        };

        assert_eq!(
            whp_vsm_protection_error_to_hv_result_ref(&error),
            (HvError::Timeout, 3)
        );
    }

    #[test]
    fn whp_vsm_protection_page_summary_preserves_gpfn_order_and_gpa_units() {
        assert_eq!(
            whp_vsm_protection_page_summary(&[0x123, 0x124, 0x125]),
            WhpVsmProtectionPageSummary {
                first_gpfn: Some(0x123),
                last_gpfn: Some(0x125),
                min_gpfn: Some(0x123),
                max_gpfn: Some(0x125),
                contiguous: true,
                first_gpa: Some(0x123000),
                last_gpa: Some(0x125000),
            }
        );
        assert!(!whp_vsm_protection_page_summary(&[3, 5, 4]).contiguous);
    }
}

impl WhpHypercallExit<'_, '_> {
    const DISPATCHER: hv1_hypercall::Dispatcher<Self> = hv1_hypercall::dispatcher!(
        Self,
        [
            hv1_hypercall::HvPostMessage,
            hv1_hypercall::HvSignalEvent,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvRetargetDeviceInterrupt,
            hv1_hypercall::HvGetVpRegisters,
            hv1_hypercall::HvSetVpRegisters,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvVtlReturn,
            hv1_hypercall::HvInstallIntercept,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvX64TranslateVirtualAddress,
            #[cfg(guest_arch = "aarch64")]
            hv1_hypercall::HvAarch64TranslateVirtualAddressEx,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvX64TranslateVirtualAddressEx,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvAssertVirtualInterrupt,
            hv1_hypercall::HvPostMessageDirect,
            hv1_hypercall::HvSignalEventDirect,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvX64EnableVpVtl,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvX64StartVirtualProcessor,
            hv1_hypercall::HvModifyVtlProtectionMask,
            #[cfg(guest_arch = "x86_64")]
            hv1_hypercall::HvGetVpIndexFromApicId,
            hv1_hypercall::HvAcceptGpaPages,
            hv1_hypercall::HvModifySparseGpaPageHostVisibility,
            hv1_hypercall::HvExtQueryCapabilities,
            hv1_hypercall::HvVbsVmCallReport,
        ]
    );
}

impl hv1_hypercall::ExtendedQueryCapabilities for WhpHypercallExit<'_, '_> {
    fn query_extended_capabilities(&mut self) -> hvdef::HvResult<u64> {
        Err(HvError::InvalidHypercallCode)
    }
}

impl hv1_hypercall::PostMessage for WhpHypercallExit<'_, '_> {
    fn post_message(&mut self, connection_id: u32, message: &[u8]) -> hvdef::HvResult<()> {
        tracing::trace!(connection_id, "post_message");
        match self.vp.vp.partition.synic_ports.handle_post_message(
            self.vp.state.active_vtl,
            connection_id,
            false,
            message,
        ) {
            Err(HvError::InvalidConnectionId) => {
                if let Some(intercept_state) = self.vp.intercept_state() {
                    if intercept_state.contains(vtl2::InterceptType::UnknownSynicConnection)
                        && self.vp.state.active_vtl == Vtl::Vtl0
                    {
                        self.reflect_to_vtl2();
                        return Err(HvError::Timeout);
                    }
                }
                Err(HvError::InvalidConnectionId)
            }
            r => r,
        }
    }
}

impl hv1_hypercall::SignalEvent for WhpHypercallExit<'_, '_> {
    fn signal_event(&mut self, connection_id: u32, flag: u16) -> hvdef::HvResult<()> {
        match self.vp.vp.partition.synic_ports.handle_signal_event(
            self.vp.state.active_vtl,
            connection_id,
            flag,
        ) {
            Err(HvError::InvalidConnectionId) => {
                if let Some(intercept_state) = self.vp.intercept_state() {
                    if intercept_state.contains(vtl2::InterceptType::UnknownSynicConnection)
                        && self.vp.state.active_vtl == Vtl::Vtl0
                    {
                        self.reflect_to_vtl2();
                        return Err(HvError::Timeout);
                    }
                }
                Err(HvError::InvalidConnectionId)
            }
            r => r,
        }
    }
}

impl hv1_hypercall::PostMessageDirect for WhpHypercallExit<'_, '_> {
    fn post_message_direct(
        &mut self,
        partition_id: u64,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        message: &hvdef::HvMessage,
    ) -> hvdef::HvResult<()> {
        tracing::trace!(
            partition_id,
            vp_index = vp,
            sint,
            typ = ?message.header.typ,
            "post_message_direct"
        );

        if sint as usize >= hvdef::NUM_SINTS
            || partition_id != HV_PARTITION_ID_SELF
            || (vp != HV_VP_INDEX_SELF && vp != self.vp.vp.index.index())
        {
            return Err(HvError::InvalidParameter);
        }

        if self.vp.state.active_vtl != Vtl::Vtl2 {
            tracing::trace!(active_vtl = ?self.vp.state.active_vtl, "invalid vtl called post_message_direct");
            return Err(HvError::OperationDenied);
        }

        self.vp.post_message(vtl, sint, message)
    }
}

impl hv1_hypercall::SignalEventDirect for WhpHypercallExit<'_, '_> {
    fn signal_event_direct(
        &mut self,
        partition_id: u64,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        flag: u16,
    ) -> hvdef::HvResult<hvdef::hypercall::SignalEventDirectOutput> {
        let vp = VpIndex::new(vp);
        tracing::trace!(
            partition_id,
            vp_index = vp.index(),
            sint,
            flag,
            "signal_event_direct"
        );
        if sint as usize >= hvdef::NUM_SINTS || sint == 0 || partition_id != HV_PARTITION_ID_SELF {
            return Err(HvError::InvalidParameter);
        }

        if self.vp.state.active_vtl != Vtl::Vtl2 {
            tracing::trace!(active_vtl = ?self.vp.state.active_vtl, "invalid vtl called set_event_direct");
            return Err(HvError::OperationDenied);
        }

        let target_vp = self.vp.vp.partition.vp(vp).ok_or(HvError::InvalidVpIndex)?;

        let newly_signaled = match &self.vp.vp.partition.hvstate {
            Hv1State::Disabled => {
                tracelimit::warn_ratelimited!(
                    ?vtl,
                    vp = vp.index(),
                    sint,
                    flag,
                    "no target synic for HvSignalEventDirect"
                );

                return Err(HvError::InvalidSynicState);
            }
            Hv1State::Emulated(hv) => hv.synic[vtl]
                .signal_event(
                    vp,
                    sint,
                    flag,
                    &mut self.vp.vp.partition.synic_interrupt(vp, vtl),
                )
                .map_err(|_| HvError::InvalidSynicState)?,
            Hv1State::Offloaded => {
                let newly_signaled =
                    target_vp
                        .whp(vtl)
                        .signal_synic_event(sint, flag)
                        .map_err(|err| match err.hv_result().map(HvError::from) {
                            Some(err @ HvError::InvalidSynicState) => err,
                            _ => {
                                tracing::error!(
                                    vp = vp.index(),
                                    sint,
                                    flag,
                                    error = &err as &dyn std::error::Error,
                                    "failed to signal synic"
                                );
                                HvError::OperationFailed
                            }
                        })?;

                if newly_signaled {
                    target_vp.ensure_vtl_runnable(vtl);
                }
                newly_signaled
            }
        };

        Ok(hvdef::hypercall::SignalEventDirectOutput {
            newly_signaled: newly_signaled as u8,
            rsvd: [0; 7],
        })
    }
}

impl hv1_hypercall::GetVpRegisters for WhpHypercallExit<'_, '_> {
    fn get_vp_registers(
        &mut self,
        partition_id: u64,
        vp_index: u32,
        vtl: Option<Vtl>,
        registers: &[hvdef::HvRegisterName],
        output: &mut [hvdef::HvRegisterValue],
    ) -> HvRepResult {
        let target = RegisterTarget::from_option(vtl);
        tracing::debug!(
            active_vtl = ?self.vp.state.active_vtl,
            partition_id,
            vp_index,
            ?target,
            ?registers,
            "get_vp_registers"
        );
        if partition_id != HV_PARTITION_ID_SELF || vp_index != HV_VP_INDEX_SELF {
            return Err((HvError::InvalidParameter, 0));
        }

        let whp_vsm = self.vp.vp.partition.vsm.lock().is_whp();
        if !whp_vsm {
            if let RegisterTarget::Vtl(vtl) = target
                && vtl > self.vp.state.active_vtl
            {
                return Err((HvError::AccessDenied, 0));
            }
        }

        for (i, (&name, output)) in zip(registers, output).enumerate() {
            match self.vp.get_vp_register(target, name) {
                Ok(value) => {
                    tracing::debug!(
                        active_vtl = ?self.vp.state.active_vtl,
                        ?target,
                        ?name,
                        ?value,
                        "get_vp_registers returned register"
                    );
                    *output = value;
                }
                Err(err) => {
                    tracing::debug!(
                        active_vtl = ?self.vp.state.active_vtl,
                        ?target,
                        ?name,
                        error = ?err,
                        "get_vp_registers rejected register"
                    );
                    return Err((err, i));
                }
            }
        }
        Ok(())
    }
}

impl hv1_hypercall::SetVpRegisters for WhpHypercallExit<'_, '_> {
    fn set_vp_registers(
        &mut self,
        partition_id: u64,
        vp_index: u32,
        vtl: Option<Vtl>,
        registers: &[hvdef::hypercall::HvRegisterAssoc],
    ) -> HvRepResult {
        let target = RegisterTarget::from_option(vtl);
        if partition_id != HV_PARTITION_ID_SELF || vp_index != HV_VP_INDEX_SELF {
            return Err((HvError::InvalidParameter, 0));
        }

        let whp_vsm = self.vp.vp.partition.vsm.lock().is_whp();
        if !whp_vsm {
            if let RegisterTarget::Vtl(vtl) = target
                && vtl > self.vp.state.active_vtl
            {
                return Err((HvError::AccessDenied, 0));
            }
        }

        for (i, reg) in registers.iter().enumerate() {
            if let Err(err) = self.vp.set_vp_register(target, reg.name, &reg.value) {
                return Err((err, i));
            }
        }
        Ok(())
    }
}

impl hv1_hypercall::InstallIntercept for WhpHypercallExit<'_, '_> {
    fn install_intercept(
        &mut self,
        partition_id: u64,
        access_type_mask: u32,
        intercept_type: HvInterceptType,
        intercept_parameters: hvdef::hypercall::HvInterceptParameters,
    ) -> hvdef::HvResult<()> {
        tracing::trace!(
            partition_id,
            access_type_mask,
            ?intercept_type,
            ?intercept_parameters,
            "install intercept call"
        );

        if let Some(state) = self.vp.intercept_state() {
            match intercept_type {
                HvInterceptType::HvInterceptTypeX64IoPort => {
                    let intercept = vtl2::InterceptType::IoPort(intercept_parameters.io_port());
                    if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                        let result = state.remove(intercept);
                        tracing::trace!(?intercept, result, "removed io intercept")
                    } else {
                        let result = state.install(intercept);
                        tracing::trace!(?intercept, result, "installed io intercept");
                    }
                }
                HvInterceptType::HvInterceptTypeX64IoPortRange => {
                    let range = intercept_parameters.io_port_range();
                    for port in range.clone() {
                        let intercept = vtl2::InterceptType::IoPort(port);
                        if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                            state.remove(intercept);
                        } else {
                            state.install(intercept);
                        }
                    }
                    if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                        tracing::trace!(?range, "removed io range intercept")
                    } else {
                        tracing::trace!(?range, "installed io range intercept");
                    }
                }
                HvInterceptType::HvInterceptTypeX64Msr => {
                    if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                        let result = state.remove(vtl2::InterceptType::Msr);
                        tracing::trace!(result, "removed msr intercept");
                    } else {
                        let result = state.install(vtl2::InterceptType::Msr);
                        tracing::trace!(result, "installed msr intercept");
                    }
                }
                HvInterceptType::HvInterceptTypeX64ApicEoi => {
                    if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                        let result = state.remove(vtl2::InterceptType::Eoi);
                        tracing::trace!(result, "removed eoi intercept");
                    } else if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_WRITE {
                        let result = state.install(vtl2::InterceptType::Eoi);
                        tracing::trace!(result, "installed eoi intercept");
                    } else {
                        panic!("EOI doesn't allow READ access")
                    }
                }
                HvInterceptType::HvInterceptTypeUnknownSynicConnection => {
                    if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                        let result = state.remove(vtl2::InterceptType::UnknownSynicConnection);
                        tracing::trace!(result, "removed unknown synic connection intercept");
                    } else {
                        let result = state.install(vtl2::InterceptType::UnknownSynicConnection);
                        tracing::trace!(result, "installed unknown synic connection intercept");
                    }
                }
                HvInterceptType::HvInterceptTypeRetargetInterruptWithUnknownDeviceId => {
                    if access_type_mask == hvdef::hypercall::HV_INTERCEPT_ACCESS_MASK_NONE {
                        let result = state.remove(vtl2::InterceptType::RetargetUnknownDeviceId);
                        tracing::trace!(result, "removed retarget unknown device id intercept");
                    } else {
                        let result = state.install(vtl2::InterceptType::RetargetUnknownDeviceId);
                        tracing::trace!(result, "installed retarget unknown device id intercept");
                    }
                }
                HvInterceptType::HvInterceptTypeException => {
                    // This intercept currently enables capturing VTL0 debugging exceptions for
                    // Hyper-V created and gdbstub enabled VMs. Implementing this would enable
                    // hardware debugging capabilities for OpenVMM managed VMs.
                    tracing::error!("HvInterceptTypeException not implemented");
                }
                _ => {
                    tracing::error!(?intercept_type, "unimplemented install intercept type");
                    return Err(HvError::InvalidParameter);
                }
            }
        }

        Ok(())
    }
}

impl hv1_hypercall::ModifyVtlProtectionMask for WhpHypercallExit<'_, '_> {
    fn modify_vtl_protection_mask(
        &mut self,
        partition_id: u64,
        map_flags: HvMapGpaFlags,
        target_vtl: Option<Vtl>,
        gpa_pages: &[u64],
    ) -> HvRepResult {
        if partition_id != HV_PARTITION_ID_SELF {
            return Err((HvError::AccessDenied, 0));
        }

        let partition = self.vp.vp.partition;
        {
            let vsm = partition.vsm.lock();
            if vsm.is_whp() {
                let vp_index = self.vp.vp.index;
                let whp_input_vtl = vsm.input_vtl(target_vtl).0;
                let pages = whp_vsm_protection_page_summary(gpa_pages);
                let result = vsm.modify_vtl_protection_mask(
                    &partition.vtl0.whp,
                    vp_index,
                    map_flags,
                    target_vtl,
                    gpa_pages,
                );
                if let Err(error) = &result {
                    let (hv_error, processed) = whp_vsm_protection_error_to_hv_result_ref(error);
                    let whp_error = error.whp_error();
                    tracing::debug!(
                        software_active_vtl = ?self.vp.state.active_vtl,
                        vp_index = vp_index.index(),
                        target_current = target_vtl.is_none(),
                        ?target_vtl,
                        whp_input_vtl,
                        page_count = gpa_pages.len(),
                        first_gpfn = pages.first_gpfn,
                        last_gpfn = pages.last_gpfn,
                        min_gpfn = pages.min_gpfn,
                        max_gpfn = pages.max_gpfn,
                        contiguous = pages.contiguous,
                        first_gpa = pages.first_gpa,
                        last_gpa = pages.last_gpa,
                        flags = u32::from(map_flags),
                        whp_hresult = whp_error.map(|error| error.code() as u32),
                        whp_hv_status = whp_error
                            .and_then(whp::WHvError::hv_result)
                            .map(|status| status.get()),
                        pages_processed = processed,
                        failed_gpfn = gpa_pages.get(processed).copied(),
                        ?hv_error,
                        whp_result = if hv_error == HvError::Timeout {
                            "timeout"
                        } else {
                            "failure"
                        },
                        error = error as &dyn std::error::Error,
                        "WHP VSM protection failed"
                    );
                }
                return result
                    .map(|_| ())
                    .map_err(whp_vsm_protection_error_to_hv_result);
            }
        }

        // TODO: Target VTL must be 2, or current executing VTL. Current VTL2
        //       must be 2. Do not support VTL changes from lower VTLs yet.
        if self.vp.state.active_vtl != Vtl::Vtl2 {
            return Err((HvError::AccessDenied, 0));
        }

        if !self
            .vp
            .vp
            .partition
            .vtl2_emulation
            .as_ref()
            .expect("vtl2 is checked to be present")
            .vsm_config()
            .enable_vtl_protection()
        {
            tracing::trace!(
                "modify vtl2 protection mask called without vsm_config enable_vtl_protection set"
            );
            return Err((HvError::AccessDenied, 0));
        }

        match target_vtl {
            None | Some(Vtl::Vtl2) => {}
            _ => {
                tracing::error!(
                    ?target_vtl,
                    "unsupported vtl for modify_vtl_protection_mask"
                );
                return Err((HvError::InvalidParameter, 0));
            }
        }

        let vtl_access = map_flags
            .try_into()
            .map_err(|_| (HvError::InvalidParameter, 0))?;

        // NOTE: Use first hypercall for vtl protections as signal for usermode
        // starting to map deferred ram.
        self.vp
            .current_vtlp()
            .map_deferred()
            .expect("committing deferred mappings cannot fail, partition in inconsistent state");

        let apply_protections = |pfn_range: RangeInclusive<u64>| -> hvdef::HvResult<()> {
            let partition = self.vp.vp.partition;
            let base_addr = pfn_range.start() * HV_PAGE_SIZE;
            let size = (pfn_range.end() - pfn_range.start() + 1) * HV_PAGE_SIZE;

            // According to the hypervisor, the page must be a memory backed
            // page. For now, additionally constrain that it must lay in the
            // memory layout, or the optional VTL2 range.
            //
            // TODO: fast lookup with range_map/bsearch?
            let mut current_base = base_addr;
            let mut remaining_size = size;
            for mem in partition
                .mem_layout
                .ram()
                .iter()
                .map(|x| &x.range)
                .chain(partition.mem_layout.vtl2_range().iter())
            {
                if current_base >= mem.start() && current_base < mem.end() {
                    if mem.end() > current_base + remaining_size {
                        remaining_size = 0;
                        break;
                    } else {
                        let covered_size = mem.end() - current_base;
                        remaining_size -= covered_size;
                        current_base += covered_size;
                    }
                }
            }

            if remaining_size != 0 {
                tracing::error!(
                    ?pfn_range,
                    "ModifyVtlProtectionMask called for non-ram range"
                );
                return Err(HvError::InvalidParameter);
            }

            // TODO: Note that this implementation of VTL protections is more
            //       permissive than it should be. Today, OpenVMM only supports a
            //       single GuestMemory struct which contains the VTL2 ranges,
            //       which means that devices can still do DMA on behalf of VTL0
            //       targeting VTL2 protected memory. This requires a rethink
            //       and redesign of memory mapping and devices so defer that to
            //       the future.
            partition
                .vtl0
                .apply_vtl_protection(base_addr, size, vtl_access)
                .expect("BUGBUG failure means return from hypercall?");

            if let Some(offset) = partition.vtl0_alias_map_offset {
                partition
                    .vtl2
                    .as_ref()
                    .expect("must have vtl2")
                    .apply_vtl_protection(base_addr | offset, size, vtl_access)
                    .expect("BUGBUG do we panic now because inconsistent state?");
            }

            // Track which pages are VTL2 restricted to fail emulation requests
            // on these gpas. Pages where access is being restored will be
            // removed from this tracking map.
            let mut restricted_pages = partition
                .vtl2_emulation
                .as_ref()
                .expect("must be set")
                .protected_pages
                .write();

            // Remove overlaps and reinsert lower and upper ranges, if any. The
            // new protection call overrides any overlaps.
            let removed = restricted_pages.remove_range(pfn_range.clone());

            if let Some(lower) = removed.first() {
                if *pfn_range.start() != 0 && lower.0 < (*pfn_range.start() - 1) {
                    assert!(restricted_pages.insert(lower.0..=(*pfn_range.start() - 1), lower.2));
                }
            }

            if let Some(upper) = removed.last() {
                if *pfn_range.end() != u64::MAX && upper.1 > pfn_range.end() + 1 {
                    assert!(restricted_pages.insert(*pfn_range.end() + 1..=upper.1, upper.2));
                }
            }

            // Track this protection call only if not restoring protections.
            if vtl_access != VtlAccess::FullAccess {
                assert!(restricted_pages.insert(pfn_range, vtl_access));
            }

            // Merge adjacent ranges for easier tracking.
            restricted_pages.merge_adjacent(range_map_vec::u64_is_adjacent);

            Ok(())
        };

        let mut pfn_range: Option<RangeInclusive<u64>> = None;
        let mut completed = 0;
        for (i, page) in gpa_pages.iter().enumerate() {
            // Consume consecutive pages to batch checks and WHP unmap calls, as
            // page by page is painfully slow.
            match pfn_range {
                Some(range) => {
                    if *page == *range.end() + 1 {
                        pfn_range = Some(*range.start()..=*page);
                    } else {
                        // This page is not consecutive with the current range,
                        // so apply protections and start a new range.
                        apply_protections(range).map_err(|e| (e, completed))?;
                        completed = i;
                        pfn_range = Some(*page..=*page);
                    }
                }
                None => {
                    pfn_range = Some(*page..=*page);
                }
            }
        }

        if let Some(range) = pfn_range {
            apply_protections(range).map_err(|e| (e, completed))?;
        }

        Ok(())
    }
}

impl hv1_hypercall::AcceptGpaPages for WhpHypercallExit<'_, '_> {
    fn accept_gpa_pages(
        &mut self,
        partition_id: u64,
        page_attributes: hvdef::hypercall::AcceptPagesAttributes,
        vtl_permission_set: hvdef::hypercall::VtlPermissionSet,
        gpa_page_base: u64,
        page_count: usize,
    ) -> HvRepResult {
        if partition_id != HV_PARTITION_ID_SELF {
            return Err((HvError::AccessDenied, 0));
        }

        let partition = self.vp.vp.partition;
        {
            let vsm = partition.vsm.lock();
            if vsm.is_whp() {
                return vsm
                    .accept_gpa_pages_no_security_shim(
                        &partition.vtl0.whp,
                        page_attributes,
                        vtl_permission_set,
                        gpa_page_base,
                        page_count,
                    )
                    .map_err(whp_vsm_protection_error_to_hv_result);
            }
        }

        let visibility = match page_attributes.host_visibility() {
            HostVisibilityType::PRIVATE => PageVisibility::Exclusive,
            HostVisibilityType::SHARED => PageVisibility::Shared,
            _ => return Err((HvError::InvalidParameter, 0)),
        };

        // If bit 2 is set, VTL2 permissions will be applied after pages are accepted, by looking at
        //  the vtl_permission_set. Obtain the vtl_access flags here.
        //
        // TODO: doesn't handle VTL1
        let vtl_access = if page_attributes.vtl_set() == 1 << 2 {
            let map_flags = HvMapGpaFlags::from(vtl_permission_set.vtl_permission_from_1[1] as u32);

            let vtl_access = map_flags
                .try_into()
                .map_err(|_| (HvError::InvalidParameter, 0))?;

            Some(vtl_access)
        } else {
            None
        };

        tracing::trace!(gpa_page_base, page_count, "accept gpa pages hypercall");

        let range =
            MemoryRange::from_4k_gpn_range(gpa_page_base..(gpa_page_base + page_count as u64));
        partition
            .vtl0
            .accept_pages(&range, visibility)
            .expect("BUGBUG return error");

        if let Some(vtl2) = &partition.vtl2 {
            vtl2.accept_pages(&range, visibility)
                .expect("BUGBUG return error");
        }

        // Apply VTL2 permissions after pages are accepted
        //
        // TODO: doesn't handle VTL1
        if page_attributes.vtl_set() == 1 << 2 {
            let vtl_access = vtl_access.unwrap();
            partition
                .vtl0
                .apply_vtl_protection(range.start(), range.len(), vtl_access)
                .expect("BUGBUG return error");
        }

        Ok(())
    }
}

impl hv1_hypercall::ModifySparseGpaPageHostVisibility for WhpHypercallExit<'_, '_> {
    fn modify_gpa_visibility(
        &mut self,
        partition_id: u64,
        visibility: HostVisibilityType,
        gpa_pages: &[u64],
    ) -> HvRepResult {
        if partition_id != HV_PARTITION_ID_SELF {
            return Err((HvError::AccessDenied, 0));
        }

        let partition = self.vp.vp.partition;
        {
            let vsm = partition.vsm.lock();
            if vsm.is_whp() {
                return vsm
                    .modify_sparse_gpa_page_host_visibility(
                        &partition.vtl0.whp,
                        visibility,
                        gpa_pages,
                    )
                    .map_err(whp_vsm_protection_error_to_hv_result);
            }
        }

        let visibility = match visibility {
            HostVisibilityType::PRIVATE => PageVisibility::Exclusive,
            HostVisibilityType::SHARED => PageVisibility::Shared,
            _ => return Err((HvError::InvalidParameter, 0)),
        };

        for (index, page) in gpa_pages.iter().enumerate() {
            let range = MemoryRange::from_4k_gpn_range(*page..(*page + 1));

            // On VBS, the page must be accepted in order to change visibility.
            // If the page is not accepted, the hypervisor returns operation
            // denied.
            let gpa = *page * HV_PAGE_SIZE;
            if partition.vtl0.gpa_visibility(gpa).is_none() {
                tracing::error!(page, "modify visibility called for non-accepted page");
                return Err((HvError::OperationDenied, index));
            }

            // TODO: Modifying visibility today doesn't return any kind of
            // useful error to the guest. Need to check the hypervisor and
            // determine what the right thing to do is here.
            //
            // Note that page visibility is only kept for tracking information
            // today, it doesn't impact the host virtstack ability to DMA, as
            // all pages are treated as shared.
            partition
                .vtl0
                .modify_visibility(&range, visibility)
                .expect("cannot handle failure");

            if let Some(vtl2) = &partition.vtl2 {
                vtl2.modify_visibility(&range, visibility)
                    .expect("cannot handle failure");
            }
        }

        Ok(())
    }
}

impl hv1_hypercall::VbsVmCallReport for WhpHypercallExit<'_, '_> {
    fn vbs_vm_call_report(&self, _report_data: &[u8]) -> hvdef::HvResult<VbsVmCallReportOutput> {
        // For now, we return a dummy report.
        // TODO: Implement actual VBS VM call report generation based on report_data.
        Ok(VbsVmCallReportOutput {
            report: [0xcdu8; hvdef::hypercall::VBS_VM_MAX_REPORT_SIZE],
        })
    }
}

#[cfg(guest_arch = "x86_64")]
mod x86 {
    use super::RegisterTarget;
    use super::WhpHypercallExit;
    use crate::WhpProcessor;
    use crate::regs;
    use crate::vsm;
    use crate::vtl2;
    use arrayvec::ArrayVec;
    use hv1_hypercall::HvInterruptParameters;
    use hv1_hypercall::HvRepResult;
    use hv1_hypercall::HypercallIo;
    use hv1_hypercall::SignalEventDirect;
    use hv1_hypercall::TranslateVirtualAddressExX64;
    use hvdef::HV_PAGE_SIZE;
    use hvdef::HV_PARTITION_ID_SELF;
    use hvdef::HV_VP_INDEX_SELF;
    use hvdef::HvCacheType;
    use hvdef::HvError;
    use hvdef::HvInterceptAccessType;
    use hvdef::HvInterruptType;
    use hvdef::HvMessageType;
    use hvdef::HvRegisterGuestVsmPartitionConfig;
    use hvdef::HvRegisterName;
    use hvdef::HvRegisterValue;
    use hvdef::HvRegisterVsmPartitionConfig;
    use hvdef::HvRegisterVsmVpSecureVtlConfig;
    use hvdef::HvResult;
    use hvdef::HvVpAssistPageActionSignalEvent;
    use hvdef::HvX64RegisterName;
    use hvdef::Vtl;
    use hvdef::hypercall::TranslateGvaControlFlagsX64;
    use hvdef::hypercall::TranslateGvaResultCode;
    use std::mem::offset_of;
    use std::sync::atomic::Ordering;
    use thiserror::Error;
    use tracing_helpers::ErrorValueExt;
    use virt::VpIndex;

    use virt_support_x86emu::translate::TranslateCachingInfo;
    use virt_support_x86emu::translate::TranslateFlags;
    use virt_support_x86emu::translate::TranslateResult;
    use virt_support_x86emu::translate::translate_gva_to_gpa;
    use vmcore::vpci_msi::VpciInterruptParameters;
    use whp::RegisterName;
    use whp::RegisterValue;
    use whp::abi::WHV_REGISTER_VALUE;
    use zerocopy::FromBytes;
    use zerocopy::FromZeros;
    use zerocopy::IntoBytes;

    #[derive(Debug, Error)]
    #[error(
        "WHP VSM VTL switch hypercall exited to OpenVMM: code={code:?}, rip={rip:#x}, active_vtl={active_vtl:?}, fast={fast}"
    )]
    pub(crate) struct WhpVsmVtlSwitchExit {
        code: hvdef::HypercallCode,
        rip: u64,
        active_vtl: Vtl,
        fast: bool,
    }

    fn whp_segment_register(
        reg: hvdef::HvX64SegmentRegister,
    ) -> whp::abi::WHV_X64_SEGMENT_REGISTER {
        whp::abi::WHV_X64_SEGMENT_REGISTER {
            Base: reg.base,
            Limit: reg.limit,
            Selector: reg.selector,
            Attributes: reg.attributes,
        }
    }

    fn whp_table_register(reg: hvdef::HvX64TableRegister) -> whp::abi::WHV_X64_TABLE_REGISTER {
        whp::abi::WHV_X64_TABLE_REGISTER {
            Pad: reg.pad,
            Limit: reg.limit,
            Base: reg.base,
        }
    }

    fn whp_initial_vp_context(
        context: &hvdef::hypercall::InitialVpContextX64,
    ) -> whp::abi::WHV_INITIAL_VP_CONTEXT {
        whp::abi::WHV_INITIAL_VP_CONTEXT {
            Rip: context.rip,
            Rsp: context.rsp,
            Rflags: context.rflags,
            Cs: whp_segment_register(context.cs),
            Ds: whp_segment_register(context.ds),
            Es: whp_segment_register(context.es),
            Fs: whp_segment_register(context.fs),
            Gs: whp_segment_register(context.gs),
            Ss: whp_segment_register(context.ss),
            Tr: whp_segment_register(context.tr),
            Ldtr: whp_segment_register(context.ldtr),
            Idtr: whp_table_register(context.idtr),
            Gdtr: whp_table_register(context.gdtr),
            Efer: context.efer,
            Cr0: context.cr0,
            Cr3: context.cr3,
            Cr4: context.cr4,
            MsrCrPat: context.msr_cr_pat,
        }
    }

    fn vsm_access_error_to_hv_error(err: vsm::VsmError) -> HvError {
        let hv_error = super::whp_vsm_error_to_hv_error(&err);
        tracing::trace!(
            error = &err as &dyn std::error::Error,
            ?hv_error,
            "VSM access validation failed"
        );
        hv_error
    }

    fn vsm_register_error_to_hv_error(err: vsm::VsmError) -> HvError {
        match err {
            vsm::VsmError::WhpTimeout(err) => {
                tracing::debug!(
                    error = &err as &dyn std::error::Error,
                    "VSM register access timed out"
                );
                HvError::Timeout
            }
            vsm::VsmError::GuestVsmHostSupportRequired(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "updated WHP Guest VSM host support required"
                );
                HvError::UnknownRegisterName
            }
            vsm::VsmError::Whp(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "VSM register access failed"
                );
                if err.is_timeout() {
                    HvError::Timeout
                } else {
                    err.hv_result()
                        .map_or(HvError::InvalidParameter, HvError::from)
                }
            }
            err => vsm_access_error_to_hv_error(err),
        }
    }

    fn enable_vp_vtl_error_to_hv_error(err: vsm::VsmError) -> HvError {
        match err {
            vsm::VsmError::InvalidVpIndex(_) => HvError::InvalidVpIndex,
            vsm::VsmError::VpVtlAlreadyEnabled { .. } => HvError::VtlAlreadyEnabled,
            vsm::VsmError::Whp(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "failed to enable VSM VP VTL"
                );
                err.hv_result()
                    .map_or(HvError::OperationFailed, HvError::from)
            }
            err => {
                tracing::trace!(
                    error = &err as &dyn std::error::Error,
                    "VSM VP VTL enable rejected"
                );
                HvError::InvalidParameter
            }
        }
    }

    fn is_64bit_hypercall(
        vp: &WhpProcessor<'_>,
        exit_context: &whp::abi::WHV_VP_EXIT_CONTEXT,
    ) -> bool {
        match whp::get_registers!(
            vp.current_whp(),
            [whp::Register64::Cr0, whp::Register64::Efer]
        ) {
            Ok((cr0, efer)) => cr0 & x86defs::X64_CR0_PE != 0 && efer & x86defs::X64_EFER_LMA != 0,
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "failed to read WHP registers for hypercall mode"
                );
                exit_context.ExecutionState.Cr0Pe() && exit_context.ExecutionState.EferLma()
            }
        }
    }

    fn whp_vsm_pseudo_register_target(
        vsm: &vsm::VsmController,
        target: RegisterTarget,
    ) -> HvResult<Vtl> {
        match target {
            RegisterTarget::Vtl(vtl) => Ok(vtl),
            RegisterTarget::Current if vsm.max_vtl() == Vtl::Vtl1 => Ok(Vtl::Vtl1),
            RegisterTarget::Current => {
                tracing::error!(
                    max_vtl = ?vsm.max_vtl(),
                    "cannot resolve WHP VSM target-current pseudo-register"
                );
                Err(HvError::InvalidParameter)
            }
        }
    }

    fn translated_gpa_cache_type(cache_info: TranslateCachingInfo, pat: u64) -> u8 {
        match cache_info {
            TranslateCachingInfo::NoPaging => HvCacheType::HvCacheTypeWriteBack.0 as u8,
            TranslateCachingInfo::Paging { pat_index } => ((pat >> (pat_index * 8)) & 0xff) as u8,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use test_with_tracing::test;

        #[test]
        fn successful_translation_uses_pat_cache_type() {
            assert_eq!(
                translated_gpa_cache_type(TranslateCachingInfo::NoPaging, 0),
                HvCacheType::HvCacheTypeWriteBack.0 as u8
            );

            let pat = u64::from_le_bytes([0, 1, 4, 5, 6, 0, 1, 4]);
            for (pat_index, expected) in [0, 1, 4, 5, 6, 0, 1, 4].into_iter().enumerate() {
                assert_eq!(
                    translated_gpa_cache_type(
                        TranslateCachingInfo::Paging {
                            pat_index: pat_index as u64,
                        },
                        pat,
                    ),
                    expected
                );
            }
        }
    }

    pub(super) struct WhpHypercallRegisters<'a> {
        info: whp::abi::WHV_HYPERCALL_CONTEXT,
        rip: u64,
        rip_dirty: bool,
        xmm_dirty: u8,
        gp_dirty: u16,
        invalid_opcode: bool,
        exit_context: &'a whp::abi::WHV_VP_EXIT_CONTEXT,
    }

    const fn gp_dirty_mask(n: hv1_hypercall::X64HypercallRegister) -> u16 {
        1 << n as u16
    }

    impl hv1_hypercall::X64RegisterState for WhpHypercallExit<'_, '_> {
        fn rip(&mut self) -> u64 {
            self.registers.rip
        }

        fn set_rip(&mut self, rip: u64) {
            self.registers.rip = rip;
            self.registers.rip_dirty = true;
        }

        fn gp(&mut self, n: hv1_hypercall::X64HypercallRegister) -> u64 {
            match n {
                hv1_hypercall::X64HypercallRegister::Rax => self.registers.info.Rax,
                hv1_hypercall::X64HypercallRegister::Rbx => self.registers.info.Rbx,
                hv1_hypercall::X64HypercallRegister::Rcx => self.registers.info.Rcx,
                hv1_hypercall::X64HypercallRegister::Rdx => self.registers.info.Rdx,
                hv1_hypercall::X64HypercallRegister::R8 => self.registers.info.R8,
                hv1_hypercall::X64HypercallRegister::Rsi => self.registers.info.Rsi,
                hv1_hypercall::X64HypercallRegister::Rdi => self.registers.info.Rdi,
            }
        }

        fn set_gp(&mut self, n: hv1_hypercall::X64HypercallRegister, value: u64) {
            match n {
                hv1_hypercall::X64HypercallRegister::Rax => self.registers.info.Rax = value,
                hv1_hypercall::X64HypercallRegister::Rbx => self.registers.info.Rbx = value,
                hv1_hypercall::X64HypercallRegister::Rcx => self.registers.info.Rcx = value,
                hv1_hypercall::X64HypercallRegister::Rdx => self.registers.info.Rdx = value,
                hv1_hypercall::X64HypercallRegister::R8 => self.registers.info.R8 = value,
                hv1_hypercall::X64HypercallRegister::Rsi => self.registers.info.Rsi = value,
                hv1_hypercall::X64HypercallRegister::Rdi => self.registers.info.Rdi = value,
            }
            self.registers.gp_dirty |= gp_dirty_mask(n);
        }

        fn xmm(&mut self, n: usize) -> u128 {
            self.registers.info.XmmRegisters[n].into()
        }

        fn set_xmm(&mut self, n: usize, value: u128) {
            self.registers.info.XmmRegisters[n] = value.into();
            self.registers.xmm_dirty |= 1 << n;
        }
    }

    impl<'a, 'b> WhpHypercallExit<'a, 'b> {
        pub(super) fn reflect_to_vtl2(&mut self) {
            let regs = &mut self.registers;

            let message = hvdef::HvX64HypercallInterceptMessage {
                header: self.vp.new_intercept_header(
                    regs.exit_context.InstructionLength(),
                    HvInterceptAccessType::EXECUTE,
                ),
                rax: regs.info.Rax,
                rbx: regs.info.Rbx,
                rcx: regs.info.Rcx,
                rdx: regs.info.Rcx,
                r8: regs.info.R8,
                rsi: regs.info.Rsi,
                rdi: regs.info.Rdi,
                xmm_registers: regs.info.XmmRegisters.map(|v| u128::from(v).into()),
                flags: hvdef::HvHypercallInterceptMessageFlags::new(),
                rsvd2: [0; 3],
            };
            self.vp.vtl2_intercept(
                HvMessageType::HvMessageTypeHypercallIntercept,
                message.as_bytes(),
            );
        }

        pub fn handle(
            vp: &'a mut WhpProcessor<'b>,
            info: &whp::abi::WHV_HYPERCALL_CONTEXT,
            exit_context: &'a whp::abi::WHV_VP_EXIT_CONTEXT,
        ) -> Result<(), WhpVsmVtlSwitchExit> {
            let vpref = vp.vp;

            let is_64bit = is_64bit_hypercall(vp, exit_context);
            let registers = WhpHypercallRegisters {
                info: *info,
                rip: exit_context.Rip,
                rip_dirty: false,
                xmm_dirty: 0,
                gp_dirty: 0,
                invalid_opcode: false,
                exit_context,
            };
            let mut this = Self { vp, registers };
            let control = hvdef::hypercall::Control::from(if is_64bit {
                info.Rcx
            } else {
                (info.Rdx << 32) | (info.Rax & u32::MAX as u64)
            });
            let code = hvdef::HypercallCode(control.code());

            let whp_vsm = this.vp.vp.partition.vsm.lock().is_whp();
            if whp_vsm
                && matches!(
                    code,
                    hvdef::HypercallCode::HvCallVtlCall | hvdef::HypercallCode::HvCallVtlReturn
                )
            {
                tracing::error!(
                    active_vtl = ?this.vp.state.active_vtl,
                    vp_index = this.vp.vp.index.index(),
                    ?code,
                    fast = control.fast(),
                    rip = exit_context.Rip,
                    rax = info.Rax,
                    rcx = info.Rcx,
                    rdx = info.Rdx,
                    "WHP VSM VTL switch hypercall exited to OpenVMM"
                );
                return Err(WhpVsmVtlSwitchExit {
                    code,
                    rip: exit_context.Rip,
                    active_vtl: this.vp.state.active_vtl,
                    fast: control.fast(),
                });
            }

            WhpHypercallExit::DISPATCHER.dispatch(
                &vpref.partition.gm,
                hv1_hypercall::X64RegisterIo::new(&mut this, is_64bit),
            );
            this.flush();
            Ok(())
        }

        fn flush(&mut self) {
            let registers = &mut self.registers;
            let mut pairs = (
                ArrayVec::<_, 14>::new(),
                ArrayVec::<WHV_REGISTER_VALUE, 14>::new(),
            );
            for (reg, value, dirty) in [
                (
                    whp::Register64::Rax,
                    registers.info.Rax,
                    hv1_hypercall::X64HypercallRegister::Rax,
                ),
                (
                    whp::Register64::Rbx,
                    registers.info.Rbx,
                    hv1_hypercall::X64HypercallRegister::Rbx,
                ),
                (
                    whp::Register64::Rcx,
                    registers.info.Rcx,
                    hv1_hypercall::X64HypercallRegister::Rcx,
                ),
                (
                    whp::Register64::Rdx,
                    registers.info.Rdx,
                    hv1_hypercall::X64HypercallRegister::Rdx,
                ),
                (
                    whp::Register64::R8,
                    registers.info.R8,
                    hv1_hypercall::X64HypercallRegister::R8,
                ),
                (
                    whp::Register64::Rsi,
                    registers.info.Rsi,
                    hv1_hypercall::X64HypercallRegister::Rsi,
                ),
                (
                    whp::Register64::Rdi,
                    registers.info.Rdi,
                    hv1_hypercall::X64HypercallRegister::Rdi,
                ),
            ] {
                if registers.gp_dirty & gp_dirty_mask(dirty) != 0 {
                    pairs.0.push(reg.as_abi());
                    pairs.1.push(value.as_abi());
                }
            }
            if registers.xmm_dirty != 0 {
                pairs.extend(
                    (0..6)
                        .filter(|&i| registers.xmm_dirty & (1 << i) != 0)
                        .map(|i| {
                            (
                                whp::abi::WHV_REGISTER_NAME(
                                    whp::abi::WHvX64RegisterXmm0.0 + i as u32,
                                ),
                                WHV_REGISTER_VALUE(registers.info.XmmRegisters[i]),
                            )
                        }),
                );
            }
            if registers.rip_dirty {
                pairs.0.push(whp::Register64::Rip.as_abi());
                pairs.1.push(registers.rip.as_abi());
            }

            let (names, values) = &pairs;
            if !names.is_empty() {
                self.vp.set_active_registers(names, values).unwrap();

                registers.gp_dirty = 0;
                registers.rip_dirty = false;
                registers.xmm_dirty = 0;
            }

            if self.registers.invalid_opcode {
                assert!(names.is_empty());

                // inject an invalid opcode fault.
                let exception_event = hvdef::HvX64PendingExceptionEvent::new()
                    .with_event_pending(true)
                    .with_event_type(hvdef::HV_X64_PENDING_EVENT_EXCEPTION)
                    .with_vector(x86defs::Exception::INVALID_OPCODE.0.into());

                self.vp
                    .set_active_registers(
                        &[whp::Register128::PendingEvent.as_abi()],
                        &[WHV_REGISTER_VALUE(u128::from(exception_event).into())],
                    )
                    .unwrap();

                self.registers.invalid_opcode = false;
            }
        }
    }

    impl hv1_hypercall::RetargetDeviceInterrupt for WhpHypercallExit<'_, '_> {
        fn retarget_interrupt(
            &mut self,
            device_id: u64,
            address: u64,
            data: u32,
            params: HvInterruptParameters<'_>,
        ) -> HvResult<()> {
            let target_processors = Vec::from_iter(params.target_processors);
            let vpci_params = VpciInterruptParameters {
                vector: params.vector,
                multicast: params.multicast,
                target_processors: &target_processors,
            };

            match self.vp.current_vtlp().software_devices.retarget_interrupt(
                device_id,
                address,
                data,
                &vpci_params,
            ) {
                Err(HvError::InvalidDeviceId) => {
                    if let Some(intercept_state) = self.vp.intercept_state() {
                        if intercept_state.contains(vtl2::InterceptType::RetargetUnknownDeviceId)
                            && self.vp.state.active_vtl == Vtl::Vtl0
                        {
                            self.reflect_to_vtl2();
                            return Err(HvError::Timeout);
                        }
                    }
                    Err(HvError::InvalidDeviceId)
                }
                r => r,
            }
        }
    }

    impl hv1_hypercall::GetVpIndexFromApicId for WhpHypercallExit<'_, '_> {
        fn get_vp_index_from_apic_id(
            &mut self,
            partition_id: u64,
            target_vtl: Vtl,
            apic_ids: &[u32],
            vp_indices: &mut [u32],
        ) -> HvRepResult {
            if partition_id != HV_PARTITION_ID_SELF {
                return Err((HvError::AccessDenied, 0));
            }

            if self.vp.state.active_vtl < target_vtl {
                return Err((HvError::AccessDenied, 0));
            }

            for (i, (apic_id, vp)) in apic_ids.iter().zip(vp_indices).enumerate() {
                let target_vp = self
                    .vp
                    .vp
                    .partition
                    .vps
                    .iter()
                    .find(|vp| vp.vp_info.apic_id == *apic_id)
                    .ok_or((HvError::InvalidParameter, i))?;

                if target_vtl == Vtl::Vtl2 && !target_vp.vtl2_enable.load(Ordering::Relaxed) {
                    return Err((HvError::InvalidParameter, i));
                }

                *vp = target_vp.vp_info.base.vp_index.index();
            }

            Ok(())
        }
    }

    impl hv1_hypercall::StartVirtualProcessor<hvdef::hypercall::InitialVpContextX64>
        for WhpHypercallExit<'_, '_>
    {
        fn start_virtual_processor(
            &mut self,
            partition_id: u64,
            vp_index: u32,
            target_vtl: Vtl,
            vp_context: &hvdef::hypercall::InitialVpContextX64,
        ) -> HvResult<()> {
            if partition_id != HV_PARTITION_ID_SELF {
                return Err(HvError::AccessDenied);
            }
            let vp_index = VpIndex::new(vp_index);
            let target_vp = self
                .vp
                .vp
                .partition
                .vp(vp_index)
                .ok_or(HvError::InvalidVpIndex)?;

            if vp_index == self.vp.vp.index {
                return Err(HvError::InvalidParameter);
            }

            if self.vp.state.active_vtl < target_vtl {
                return Err(HvError::AccessDenied);
            }

            let target_vplc = target_vp.vplc(target_vtl);
            *target_vplc.start_vp_context.lock() = Some(Box::new(*vp_context));
            target_vplc.start_vp.store(true, Ordering::Release);
            target_vp.wake();
            Ok(())
        }
    }
    impl hv1_hypercall::VtlSwitchOps for WhpHypercallExit<'_, '_> {
        fn advance_ip(&mut self) {
            let is_64bit = is_64bit_hypercall(self.vp, self.registers.exit_context);
            hv1_hypercall::X64RegisterIo::new(self, is_64bit).advance_ip();
        }

        fn inject_invalid_opcode_fault(&mut self) {
            self.registers.invalid_opcode = true;
        }
    }

    impl hv1_hypercall::VtlReturn for WhpHypercallExit<'_, '_> {
        fn is_vtl_return_allowed(&self) -> bool {
            if self.vp.state.active_vtl == Vtl::Vtl0 {
                tracelimit::warn_ratelimited!("attempt to return from VTL0");
                return false;
            }

            true
        }

        fn vtl_return(&mut self, fast: bool) {
            tracing::trace!(?fast, "vtl return");

            if !fast {
                // Get the rax and rcx registers from the vp assist page.
                if let Some(base_gpa) =
                    self.vp.state.vtls[self.vp.state.active_vtl].vp_assist_page()
                {
                    match self.vp.vp.partition.gm.read_plain::<[u64; 2]>(
                        base_gpa
                            + offset_of!(hvdef::HvVpAssistPage, vtl_control) as u64
                            + offset_of!(hvdef::HvVpVtlControl, registers) as u64,
                    ) {
                        Ok([rax, rcx]) => {
                            self.registers.info.Rax = rax;
                            self.registers.info.Rcx = rcx;
                            self.registers.gp_dirty |=
                                gp_dirty_mask(hv1_hypercall::X64HypercallRegister::Rax)
                                    | gp_dirty_mask(hv1_hypercall::X64HypercallRegister::Rcx);
                        }
                        Err(err) => {
                            tracing::error!(
                                error = err.as_error(),
                                base_gpa,
                                "failed to read from vp assist page"
                            );
                        }
                    }
                }
            }

            // Read the return actions.
            if let Some(base_gpa) = self.vp.state.vtls[self.vp.state.active_vtl].vp_assist_page() {
                let actions_gpa =
                    base_gpa + offset_of!(hvdef::HvVpAssistPage, vtl_return_actions) as u64;
                match self.vp.vp.partition.gm.read_plain::<[u8; 256]>(actions_gpa) {
                    Ok(actions) => {
                        // Clear the old actions.
                        let _ = self.vp.vp.partition.gm.write_at(actions_gpa, &[0; 256]);

                        let mut offset = 0;
                        while offset < actions.len() - 8 {
                            let n = match actions[offset] {
                                0 => break,
                                1 => {
                                    let signal_event =
                                        match HvVpAssistPageActionSignalEvent::read_from_prefix(
                                            &actions[offset..],
                                        ) {
                                            Ok((v, _)) => v,
                                            Err(_) => break, // TODO: zerocopy: err (https://github.com/microsoft/openvmm/issues/759)
                                        };

                                    if let Err(err) = self.handle_action_signal_event(&signal_event)
                                    {
                                        match err {
                                            HvError::InvalidSynicState => {
                                                // This is expected.
                                                tracing::debug!(
                                                    error = ?err,
                                                    vtl = signal_event.target_vtl,
                                                    vp = signal_event.target_vp,
                                                    sint = signal_event.target_sint,
                                                    flag = signal_event.flag_number,
                                                    "failed signal event action (expected)"
                                                )
                                            }
                                            _ => {
                                                tracing::warn!(
                                                    error = ?err,
                                                    vtl = signal_event.target_vtl,
                                                    vp = signal_event.target_vp,
                                                    sint = signal_event.target_sint,
                                                    flag = signal_event.flag_number,
                                                    "failed signal event action"
                                                )
                                            }
                                        }
                                    }

                                    size_of_val(&signal_event)
                                }
                                action_type => {
                                    tracing::warn!(action_type, "unknown vp assist action");
                                    break;
                                }
                            };
                            offset += n;
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            error = err.as_error(),
                            base_gpa,
                            "failed to read from vp assist page"
                        );
                    }
                }
            }

            self.vp.state.runnable_vtls.clear(self.vp.state.active_vtl);
        }
    }

    impl WhpHypercallExit<'_, '_> {
        fn handle_action_signal_event(
            &mut self,
            signal_event: &HvVpAssistPageActionSignalEvent,
        ) -> HvResult<()> {
            let vtl = signal_event
                .target_vtl
                .try_into()
                .map_err(|_| HvError::InvalidParameter)?;

            self.signal_event_direct(
                HV_PARTITION_ID_SELF,
                vtl,
                signal_event.target_vp,
                signal_event.target_sint,
                signal_event.flag_number,
            )?;
            Ok(())
        }
    }

    impl hv1_hypercall::AssertVirtualInterrupt for WhpHypercallExit<'_, '_> {
        fn assert_virtual_interrupt(
            &mut self,
            partition_id: u64,
            interrupt_control: hvdef::HvInterruptControl,
            destination_address: u64,
            requested_vector: u32,
            target_vtl: Vtl,
        ) -> HvResult<()> {
            tracing::trace!(
                partition_id,
                ?interrupt_control,
                destination_address,
                requested_vector,
                ?target_vtl,
                "assert virtual interrupt"
            );

            match interrupt_control.interrupt_type() {
                HvInterruptType::HvX64InterruptTypeFixed
                | HvInterruptType::HvX64InterruptTypeLowestPriority
                | HvInterruptType::HvX64InterruptTypeNmi
                | HvInterruptType::HvX64InterruptTypeInit
                | HvInterruptType::HvX64InterruptTypeSipi => {}
                _ => return Err(HvError::InvalidParameter),
            }

            assert!(target_vtl == Vtl::Vtl0);

            self.vp
                .vp
                .partition
                .interrupt(
                    target_vtl,
                    virt::irqcon::MsiRequest::new_x86(
                        x86defs::apic::DeliveryMode(interrupt_control.interrupt_type().0 as u8),
                        destination_address
                            .try_into()
                            .map_err(|_| HvError::InvalidParameter)?,
                        interrupt_control.x86_logical_destination_mode(),
                        requested_vector
                            .try_into()
                            .map_err(|_| HvError::InvalidParameter)?,
                        interrupt_control.x86_level_triggered(),
                    ),
                )
                .map_err(|_| HvError::InvalidParameter)?; // TODO: translate error codes

            Ok(())
        }
    }

    fn convert_translate_control_flags(
        control_flags: TranslateGvaControlFlagsX64,
    ) -> Result<TranslateFlags, HvError> {
        let allowed_flags = TranslateGvaControlFlagsX64::new()
            .with_validate_read(true)
            .with_validate_write(true)
            .with_validate_execute(true)
            .with_privilege_exempt(true)
            .with_set_page_table_bits(true)
            .with_tlb_flush_inhibit(true)
            .with_supervisor_access(true)
            .with_user_access(true)
            .with_enforce_smap(true)
            .with_override_smap(true)
            .with_input_vtl((!0u8).into());

        if (u64::from(control_flags) & !(u64::from(allowed_flags))) != 0 {
            tracing::trace!(
                "translate gva control flags contains flags not supported by whp {:?}",
                control_flags
            );
            return Err(HvError::InvalidParameter);
        }

        Ok(TranslateFlags::from_hv_flags(control_flags))
    }

    impl hv1_hypercall::TranslateVirtualAddressX64 for WhpHypercallExit<'_, '_> {
        fn translate_virtual_address(
            &mut self,
            partition_id: u64,
            vp_index: u32,
            control_flags: TranslateGvaControlFlagsX64,
            gva_page: u64,
        ) -> HvResult<hvdef::hypercall::TranslateVirtualAddressOutput> {
            let output =
                self.translate_virtual_address_ex(partition_id, vp_index, control_flags, gva_page)?;

            Ok(hvdef::hypercall::TranslateVirtualAddressOutput {
                translation_result: output.translation_result.result,
                gpa_page: output.gpa_page,
            })
        }
    }

    impl TranslateVirtualAddressExX64 for WhpHypercallExit<'_, '_> {
        fn translate_virtual_address_ex(
            &mut self,
            partition_id: u64,
            vp_index: u32,
            control_flags: TranslateGvaControlFlagsX64,
            gva_page: u64,
        ) -> HvResult<hvdef::hypercall::TranslateVirtualAddressExOutputX64> {
            // TODO: this doesn't fully implement all the functionality of the
            // TranslateVirtualAddressEx hypercall because the underlying layers
            // currently don't return overlay page or event_pending.
            tracing::trace!(
                ?partition_id,
                ?vp_index,
                ?control_flags,
                ?gva_page,
                "translate virtual address ex"
            );

            // Not yet supported by WHP
            if partition_id != HV_PARTITION_ID_SELF || vp_index != HV_VP_INDEX_SELF {
                return Err(HvError::InvalidParameter);
            }

            // WHP currently doesn't support the INPUT_VTL_MASK set by the Underhill instruction emulator
            if control_flags.input_vtl().target_vtl()? != Some(Vtl::Vtl0) {
                todo!("WHP can only translate gvas against VTL0");
            }

            let flags = convert_translate_control_flags(control_flags)?;

            let result = translate_gva_to_gpa(
                &self.vp.vp.partition.gm,
                gva_page * HV_PAGE_SIZE,
                &self.vp.translation_registers(Vtl::Vtl0),
                flags,
            );

            let result = match result {
                Ok(TranslateResult { gpa, cache_info }) => {
                    let mut pat = [WHV_REGISTER_VALUE::default()];
                    self.vp
                        .get_vtl_registers(Vtl::Vtl0, &[whp::abi::WHvX64RegisterPat], &mut pat)
                        .map_err(vsm_register_error_to_hv_error)?;
                    let pat = u128::from(pat[0].0) as u64;
                    let cache_type = translated_gpa_cache_type(cache_info, pat);
                    hvdef::hypercall::TranslateVirtualAddressExOutputX64 {
                        translation_result: hvdef::hypercall::TranslateGvaResultExX64 {
                            result: hvdef::hypercall::TranslateGvaResult::new()
                                .with_result_code(TranslateGvaResultCode::SUCCESS.0)
                                .with_cache_type(cache_type),
                            ..FromZeros::new_zeroed()
                        },
                        gpa_page: gpa / HV_PAGE_SIZE,
                        ..FromZeros::new_zeroed()
                    }
                }
                Err(err) => hvdef::hypercall::TranslateVirtualAddressExOutputX64 {
                    translation_result: hvdef::hypercall::TranslateGvaResultExX64 {
                        result: hvdef::hypercall::TranslateGvaResult::new()
                            .with_result_code(TranslateGvaResultCode::from(err).0),
                        ..FromZeros::new_zeroed()
                    },
                    ..FromZeros::new_zeroed()
                },
            };

            Ok(result)
        }
    }

    impl hv1_hypercall::EnableVpVtl<hvdef::hypercall::InitialVpContextX64>
        for WhpHypercallExit<'_, '_>
    {
        fn enable_vp_vtl(
            &mut self,
            partition_id: u64,
            vp_index: u32,
            vtl: Vtl,
            vp_context: &hvdef::hypercall::InitialVpContextX64,
        ) -> HvResult<()> {
            if partition_id != HV_PARTITION_ID_SELF {
                return Err(HvError::AccessDenied);
            }

            let vp_index = VpIndex::new(vp_index);
            let partition = self.vp.vp.partition;
            if partition.vsm.lock().is_whp() {
                let initial_context = whp_initial_vp_context(vp_context);

                tracing::info!(
                    vp_index = vp_index.index(),
                    ?vtl,
                    ?initial_context,
                    "enabling VSM VP VTL"
                );
                partition
                    .vsm
                    .lock()
                    .enable_vp_vtl(&partition.vtl0.whp, vp_index, vtl, &initial_context)
                    .map_err(enable_vp_vtl_error_to_hv_error)?;

                if vp_index != self.vp.vp.index {
                    partition
                        .vtl0
                        .whp
                        .vp(vp_index.index())
                        .cancel_run()
                        .map_err(|err| {
                            tracing::error!(
                                vp_index = vp_index.index(),
                                error = &err as &dyn std::error::Error,
                                "failed to cancel VSM target VP"
                            );
                            HvError::OperationFailed
                        })?;
                }

                return Ok(());
            }

            if self.vp.state.active_vtl != Vtl::Vtl2 {
                return Err(HvError::AccessDenied);
            }

            let target_vp = self
                .vp
                .vp
                .partition
                .vp(vp_index)
                .ok_or(HvError::InvalidVpIndex)?;

            if vp_index == self.vp.vp.index || vtl != Vtl::Vtl2 {
                return Err(HvError::InvalidParameter);
            }

            if target_vp.vp().vtl2_enable.swap(true, Ordering::SeqCst) {
                return Err(HvError::VtlAlreadyEnabled);
            }

            let names = &[
                whp::abi::WHvX64RegisterRip,
                whp::abi::WHvX64RegisterRsp,
                whp::abi::WHvX64RegisterRflags,
                whp::abi::WHvX64RegisterCs,
                whp::abi::WHvX64RegisterDs,
                whp::abi::WHvX64RegisterEs,
                whp::abi::WHvX64RegisterFs,
                whp::abi::WHvX64RegisterGs,
                whp::abi::WHvX64RegisterSs,
                whp::abi::WHvX64RegisterTr,
                whp::abi::WHvX64RegisterLdtr,
                whp::abi::WHvX64RegisterIdtr,
                whp::abi::WHvX64RegisterGdtr,
                whp::abi::WHvX64RegisterEfer,
                whp::abi::WHvX64RegisterCr0,
                whp::abi::WHvX64RegisterCr3,
                whp::abi::WHvX64RegisterCr4,
                whp::abi::WHvX64RegisterPat,
            ];
            let values: &[HvRegisterValue] = &[
                vp_context.rip.into(),
                vp_context.rsp.into(),
                vp_context.rflags.into(),
                vp_context.cs.into(),
                vp_context.ds.into(),
                vp_context.es.into(),
                vp_context.fs.into(),
                vp_context.gs.into(),
                vp_context.ss.into(),
                vp_context.tr.into(),
                vp_context.ldtr.into(),
                vp_context.idtr.into(),
                vp_context.gdtr.into(),
                vp_context.efer.into(),
                vp_context.cr0.into(),
                vp_context.cr3.into(),
                vp_context.cr4.into(),
                vp_context.msr_cr_pat.into(),
            ];

            // SAFETY: HvRegisterValue and WHV_REGISTER_VALUE are the same.
            let values =
                unsafe { std::mem::transmute::<&[HvRegisterValue], &[WHV_REGISTER_VALUE]>(values) };

            tracing::debug!(vp_index = vp_index.index(), ?vtl, "enabling vtl");

            target_vp
                .whp(vtl)
                .set_registers(names, values)
                .map_err(|_| HvError::InvalidParameter)?;

            // Force VTL0 to return now that VTL2 is enabled.
            target_vp.whp(Vtl::Vtl0).cancel_run().expect("can't fail");
            Ok(())
        }
    }

    impl WhpProcessor<'_> {
        fn get_whp_vsm_register(
            &mut self,
            target: RegisterTarget,
            name: HvRegisterName,
        ) -> HvResult<Option<HvRegisterValue>> {
            let partition = self.vp.partition;
            let vsm = partition.vsm.lock();
            if !vsm.is_whp() {
                return Ok(None);
            }

            let get_whp_register = |name: HvRegisterName| {
                let whp_name = regs::hv_register_to_whp(HvX64RegisterName::from(name))
                    .unwrap_or(whp::abi::WHV_REGISTER_NAME(name.0));
                let mut whp_value = [Default::default(); 1];
                vsm.get_vp_registers(
                    self.vp.index,
                    partition.vtl0.whp.vp(self.vp.index.index()),
                    target.explicit(),
                    &[whp_name],
                    &mut whp_value,
                )
                .map_err(vsm_register_error_to_hv_error)?;

                // SAFETY: HvRegisterValue and WHV_REGISTER_VALUE are the same.
                Ok(unsafe {
                    std::mem::transmute::<WHV_REGISTER_VALUE, HvRegisterValue>(whp_value[0])
                })
            };

            let value = match name.into() {
                HvX64RegisterName::VsmCodePageOffsets => {
                    let value = get_whp_register(name)?;
                    let offsets = hvdef::HvRegisterVsmCodePageOffsets::from(value.as_u64());
                    tracing::info!(
                        active_vtl = ?self.state.active_vtl,
                        ?target,
                        call_offset = offsets.call_offset(),
                        return_offset = offsets.return_offset(),
                        raw = value.as_u64(),
                        "WHP VSM code page offsets returned by WHP"
                    );
                    value
                }
                HvX64RegisterName::VsmPartitionConfig => {
                    let vtl = whp_vsm_pseudo_register_target(&vsm, target)?;
                    let config = vsm
                        .vsm_partition_config(self.vp.index, vtl)
                        .map_err(vsm_access_error_to_hv_error)?;
                    u64::from(config).into()
                }
                HvX64RegisterName::GuestVsmPartitionConfig => {
                    let vtl = whp_vsm_pseudo_register_target(&vsm, target)?;
                    let config = vsm
                        .guest_vsm_partition_config(self.vp.index, vtl)
                        .map_err(vsm_access_error_to_hv_error)?;
                    u64::from(config).into()
                }
                HvX64RegisterName::VsmVpStatus => {
                    let vtl = whp_vsm_pseudo_register_target(&vsm, target)?;
                    let enabled_vtl_set = vsm
                        .partition_enabled_vtl_bits()
                        .map_err(vsm_access_error_to_hv_error)?;
                    let status = hvdef::HvRegisterVsmVpStatus::new()
                        .with_active_vtl(u8::from(vtl))
                        .with_active_mbec_enabled(false)
                        .with_enabled_vtl_set(enabled_vtl_set);
                    tracing::trace!(
                        active_vtl = ?self.state.active_vtl,
                        enabled_vtl_set,
                        "VSM VP status returned"
                    );
                    u64::from(status).into()
                }
                HvX64RegisterName::VsmCapabilities => {
                    let vtl = whp_vsm_pseudo_register_target(&vsm, target)?;
                    vsm.vsm_partition_config(self.vp.index, vtl)
                        .map_err(vsm_access_error_to_hv_error)?;
                    let capabilities = hvdef::HvRegisterVsmCapabilities::new()
                        .with_dr6_shared(!partition.caps.vendor.is_amd_compatible())
                        .with_mbec_vtl_mask(1)
                        .with_deny_lower_vtl_startup(true)
                        .with_intercept_page_available(true);
                    tracing::trace!(
                        active_vtl = ?self.state.active_vtl,
                        ?vtl,
                        ?capabilities,
                        "VSM capabilities returned"
                    );
                    u64::from(capabilities).into()
                }
                HvX64RegisterName::TimeRefCount => {
                    let Some(vtl) = target.explicit() else {
                        return get_whp_register(name).map(Some);
                    };
                    vsm.validate_vp_vtl_enabled(self.vp.index, vtl)
                        .map_err(vsm_access_error_to_hv_error)?;
                    partition
                        .vtl0
                        .whp
                        .reference_time()
                        .map_err(|err| {
                            tracing::error!(
                                error = &err as &dyn std::error::Error,
                                "failed to read VSM reference time"
                            );
                            HvError::InvalidParameter
                        })?
                        .into()
                }
                reg => {
                    let name = HvRegisterName::from(reg);
                    get_whp_register(name)?
                }
            };

            Ok(Some(value))
        }

        fn set_whp_vsm_register(
            &mut self,
            target: RegisterTarget,
            name: HvRegisterName,
            value: &HvRegisterValue,
        ) -> HvResult<Option<()>> {
            let partition = self.vp.partition;
            let vsm = partition.vsm.lock();
            if !vsm.is_whp() {
                return Ok(None);
            }

            match name.into() {
                HvX64RegisterName::VsmPartitionConfig => {
                    let vtl = whp_vsm_pseudo_register_target(&vsm, target)?;
                    let vsm_config = HvRegisterVsmPartitionConfig::from(value.as_u64());
                    let write = vsm
                        .prepare_vsm_partition_config_write(self.vp.index, vtl, vsm_config)
                        .map_err(vsm_access_error_to_hv_error)?;
                    drop(vsm);

                    tracing::debug!(
                        vp_index = write.vp_index().index(),
                        target_vtl = ?write.target_vtl(),
                        vsm_partition_config = write.value(),
                        "WHP VSM partition config requested"
                    );

                    let whp_result = partition
                        .vtl0
                        .whp
                        .vp(write.vp_index().index())
                        .set_registers_for_vtl(
                            whp::abi::WHV_INPUT_VTL::target(u8::from(write.target_vtl())),
                            &[whp::abi::WHvRegisterVsmPartitionConfig],
                            &[WHV_REGISTER_VALUE(write.value().into())],
                        )
                        .map_err(vsm::vsm_partition_config_whp_error);

                    let result = partition
                        .vsm
                        .lock()
                        .complete_vsm_partition_config_write(write, whp_result);
                    match &result {
                        Ok(()) => tracing::debug!(
                            vp_index = write.vp_index().index(),
                            target_vtl = ?write.target_vtl(),
                            vsm_partition_config = write.value(),
                            whp_result = "success",
                            local_shadow_committed = true,
                            "WHP VSM partition config completed"
                        ),
                        Err(vsm::VsmError::WhpTimeout(error)) => tracing::debug!(
                            vp_index = write.vp_index().index(),
                            target_vtl = ?write.target_vtl(),
                            vsm_partition_config = write.value(),
                            whp_result = "timeout",
                            local_shadow_committed = false,
                            error = error as &dyn std::error::Error,
                            "WHP VSM partition config incomplete"
                        ),
                        Err(error) => tracing::error!(
                            vp_index = write.vp_index().index(),
                            target_vtl = ?write.target_vtl(),
                            vsm_partition_config = write.value(),
                            whp_result = "failure",
                            local_shadow_committed = false,
                            error = error as &dyn std::error::Error,
                            "WHP VSM partition config failed"
                        ),
                    }
                    result.map_err(vsm_register_error_to_hv_error)?;
                    return Ok(Some(()));
                }
                HvX64RegisterName::GuestVsmPartitionConfig => {
                    let vtl = whp_vsm_pseudo_register_target(&vsm, target)?;
                    let guest_vsm_config = HvRegisterGuestVsmPartitionConfig::from(value.as_u64());
                    vsm.validate_guest_vsm_partition_config(self.vp.index, vtl, guest_vsm_config)
                        .map_err(vsm_access_error_to_hv_error)?;
                }
                reg => {
                    let name = HvRegisterName::from(reg);
                    let whp_name = regs::hv_register_to_whp(reg)
                        .unwrap_or(whp::abi::WHV_REGISTER_NAME(name.0));
                    // SAFETY: HvRegisterValue and WHV_REGISTER_VALUE are the same.
                    let whp_value = unsafe {
                        std::mem::transmute::<HvRegisterValue, WHV_REGISTER_VALUE>(*value)
                    };
                    vsm.set_vp_registers(
                        self.vp.index,
                        partition.vtl0.whp.vp(self.vp.index.index()),
                        target.explicit(),
                        &[whp_name],
                        &[whp_value],
                    )
                    .map_err(vsm_register_error_to_hv_error)?;
                }
            }

            Ok(Some(()))
        }

        pub(super) fn get_vp_register(
            &mut self,
            target: RegisterTarget,
            name: HvRegisterName,
        ) -> HvResult<HvRegisterValue> {
            if let Some(value) = self.get_whp_vsm_register(target, name)? {
                return Ok(value);
            }

            let vtl = target.resolve_for_emulation(self.state.active_vtl);
            let value = match name.into() {
                HvX64RegisterName::VsmCodePageOffsets => {
                    // TODO: active VTL must be 2 and only allow target current VTL.
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid vsm code page offset get registers");
                        return Err(HvError::AccessDenied);
                    }

                    let v = if let Some(hv) = &self.state.vtls[self.state.active_vtl].hv {
                        let (cr0, efer) = whp::get_registers!(
                            self.current_whp(),
                            [whp::Register64::Cr0, whp::Register64::Efer]
                        )
                        .unwrap();

                        let is_64bit =
                            cr0 & x86defs::X64_CR0_PE != 0 && efer & x86defs::X64_EFER_LMA != 0;

                        hv.vsm_code_page_offsets(is_64bit)
                    } else {
                        // These values come from the current hypervisor binary. In
                        // the future, get these from the hypervisor or map our own
                        // page.
                        //
                        // Also handle 32 bit.
                        hvdef::HvRegisterVsmCodePageOffsets::new()
                            .with_call_offset(0xf)
                            .with_return_offset(0x28)
                    };
                    u64::from(v).into()
                }
                HvX64RegisterName::VsmCapabilities => {
                    // The alias map capability is only available if the current
                    // VTL is 2.
                    let alias_map_available = self.state.active_vtl == Vtl::Vtl2
                        && self.vp.partition.vtl0_alias_map_offset.is_some();

                    // The intercept not present gpa capability is only
                    // available to VTL2. The property is always available,
                    // because WHP's implementation of VTL's does not have this
                    // distinction like Hyper-V.
                    let intercept_not_present_available = self.state.active_vtl == Vtl::Vtl2;

                    let capabilities = hvdef::HvRegisterVsmCapabilities::new()
                        .with_intercept_page_available(true)
                        .with_return_action_available(true)
                        .with_vtl0_alias_map_available(alias_map_available)
                        .with_intercept_not_present_available(intercept_not_present_available);
                    u64::from(capabilities).into()
                }
                HvX64RegisterName::VsmPartitionConfig => {
                    // TODO: Each VTL above 0 has it's own config register, but
                    //       we only support VTL2 today. Only allow VTL2 access
                    //       to the register.
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid vsm partition config get registers");
                        return Err(HvError::AccessDenied);
                    }

                    self.vp
                        .partition
                        .vtl2_emulation
                        .as_ref()
                        .expect("vtl2 is present")
                        .vsm_config_raw
                        .load(Ordering::Relaxed)
                        .into()
                }
                HvX64RegisterName::GuestVsmPartitionConfig => {
                    // TODO: WHP doesn't support guest vsm yet. Only allow VTL2
                    // access to the register.
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid guest vsm partition config get register");
                        return Err(HvError::AccessDenied);
                    }

                    u64::from(HvRegisterGuestVsmPartitionConfig::new().with_maximum_vtl(0)).into()
                }
                HvX64RegisterName::VsmVpStatus => {
                    let status = hvdef::HvRegisterVsmVpStatus::new()
                        .with_active_vtl(self.state.active_vtl as u8)
                        .with_active_mbec_enabled(false)
                        .with_enabled_vtl_set(1);
                    tracing::trace!(active_vtl = ?self.state.active_vtl, "VSM VP status returned");
                    u64::from(status).into()
                }
                HvX64RegisterName::DeliverabilityNotifications => {
                    if vtl != Vtl::Vtl0 || self.state.active_vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid get deliverability notification register");
                        return Err(HvError::AccessDenied);
                    }
                    u64::from(self.state.vtl2_deliverability_notifications).into()
                }
                HvX64RegisterName::TimeRefCount => self
                    .vp
                    .partition
                    .vtlp(vtl)
                    .whp
                    .reference_time()
                    .unwrap()
                    .into(),
                HvX64RegisterName(reg)
                    if (HvX64RegisterName::Sint0.0..=HvX64RegisterName::Sint15.0)
                        .contains(&reg)
                        && vtl == Vtl::Vtl0
                        && self.state.vtls.vtl0.hv.is_some() =>
                {
                    self.state
                        .vtls
                        .vtl0
                        .hv
                        .as_ref()
                        .unwrap()
                        .synic
                        .sint((reg - HvX64RegisterName::Sint0.0) as u8)
                        .into()
                }
                HvX64RegisterName::VsmVpSecureConfigVtl0 => {
                    // TODO: Each VTL has a register for each lower VTL, but we don't
                    // support VTL 1 yet.
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid vsm vp secure config get registers");
                        return Err(HvError::AccessDenied);
                    }

                    // WHP locks the TLB on every exit, so this is already locked.
                    u64::from(HvRegisterVsmVpSecureVtlConfig::new().with_tlb_locked(true)).into()
                }
                reg => {
                    if let Ok(name) = regs::hv_register_to_whp(reg) {
                        if vtl != Vtl::Vtl0 || self.state.active_vtl != Vtl::Vtl2 {
                            tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid get registers call");
                            return Err(HvError::AccessDenied);
                        }

                        let mut whp_value = [Default::default(); 1];
                        if let Err(err) = self
                            .vp
                            .whp(Vtl::Vtl0)
                            .get_registers(&[name], &mut whp_value)
                        {
                            tracing::error!(
                                name = ?reg,
                                whp_reg = ?name,
                                error = &err as &dyn std::error::Error,
                                "failed to get VTL0 register on behalf of VTL2"
                            );
                            return Err(HvError::InvalidParameter);
                        }

                        // SAFETY: HvRegisterValue and WHV_REGISTER_VALUE are the same.
                        unsafe {
                            std::mem::transmute::<WHV_REGISTER_VALUE, HvRegisterValue>(whp_value[0])
                        }
                    } else {
                        tracing::error!(name = ?reg, "unknown register name for get_vp_registers");
                        return Err(HvError::InvalidParameter);
                    }
                }
            };

            Ok(value)
        }

        pub(super) fn set_vp_register(
            &mut self,
            target: RegisterTarget,
            name: HvRegisterName,
            value: &HvRegisterValue,
        ) -> HvResult<()> {
            if self.set_whp_vsm_register(target, name, value)?.is_some() {
                return Ok(());
            }

            let vtl = target.resolve_for_emulation(self.state.active_vtl);
            match name.into() {
                HvX64RegisterName::VsmPartitionConfig => {
                    // TODO: active VTL must be 2 and only allow target current VTL.
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid vsm partition config set registers");
                        return Err(HvError::AccessDenied);
                    }

                    // TODO: Perform validation of the values set.
                    let value = value.as_u64();

                    self.vp
                        .partition
                        .vtl2_emulation
                        .as_ref()
                        .unwrap()
                        .vsm_config_raw
                        .store(value, Ordering::Relaxed);

                    let vsm_config = HvRegisterVsmPartitionConfig::from(value);

                    tracing::trace!(?vsm_config, "set VsmPartitionConfig");
                }
                HvX64RegisterName::DeliverabilityNotifications => {
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl0 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid set deliverability notification register");
                        return Err(HvError::AccessDenied);
                    }

                    let supported = hvdef::HvDeliverabilityNotificationsRegister::new()
                        .with_sints(!0)
                        .with_interrupt_notification(true);

                    if value.as_u64() & !u64::from(supported) != 0 {
                        return Err(HvError::InvalidParameter);
                    }

                    self.state.vtl2_deliverability_notifications = value.as_u64().into();
                    self.update_deliverability_notifications(
                        Vtl::Vtl0,
                        self.state.vtls.vtl0.deliverability_notifications,
                    );
                }
                HvX64RegisterName::PendingEvent1 => {}

                HvX64RegisterName::VsmVpSecureConfigVtl0 => {
                    // TODO: Each VTL has a register for each lower VTL, but we don't
                    // support VTL 1 yet.
                    if self.state.active_vtl != Vtl::Vtl2 || vtl != Vtl::Vtl2 {
                        tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid vsm vp secure config get registers");
                        return Err(HvError::AccessDenied);
                    }

                    // WHP locks the TLB on every exit, so this is already locked.
                    // Make sure the guest isn't trying to unlock.
                    if !HvRegisterVsmVpSecureVtlConfig::from(value.as_u64()).tlb_locked() {
                        return Err(HvError::InvalidParameter);
                    }
                }

                reg => {
                    if let Ok(name) = regs::hv_register_to_whp(reg) {
                        if vtl != Vtl::Vtl0 || self.state.active_vtl != Vtl::Vtl2 {
                            tracelimit::error_ratelimited!(active_vtl = ?self.state.active_vtl, "invalid set registers call");
                            return Err(HvError::AccessDenied);
                        }

                        // SAFETY: HvRegisterValue and WHV_REGISTER_VALUE are the same.
                        let whp_value = unsafe {
                            std::mem::transmute::<HvRegisterValue, WHV_REGISTER_VALUE>(*value)
                        };
                        if let Err(err) =
                            self.vp.whp(Vtl::Vtl0).set_registers(&[name], &[whp_value])
                        {
                            tracing::error!(
                                name = ?reg,
                                whp_reg = ?name,
                                error = &err as &dyn std::error::Error,
                                "failed to set VTL0 register on behalf of VTL2"
                            );
                            return Err(HvError::InvalidParameter);
                        }
                    } else {
                        tracing::error!(name = ?reg, "unknown register name for set_vp_registers");
                        return Err(HvError::InvalidParameter);
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(guest_arch = "aarch64")]
mod aarch64 {
    use super::RegisterTarget;
    use super::WhpHypercallExit;
    use crate::WhpProcessor;
    use crate::regs;
    use arrayvec::ArrayVec;
    use hvdef::HV_PAGE_SIZE;
    use hvdef::HV_PARTITION_ID_SELF;
    use hvdef::HV_VP_INDEX_SELF;
    use hvdef::HvArm64RegisterName;
    use hvdef::HvError;
    use hvdef::HvRegisterName;
    use hvdef::HvRegisterValue;
    use hvdef::HvResult;
    use hvdef::Vtl;
    use hvdef::hypercall::TranslateGvaControlFlagsArm64;
    use hvdef::hypercall::TranslateGvaResultCode;
    use virt_support_aarch64emu::translate::TranslateFlags;
    use virt_support_aarch64emu::translate::TranslationRegisters;
    use virt_support_aarch64emu::translate::translate_gva_to_gpa;
    use whp::RegisterValue;
    use zerocopy::FromZeros;

    pub(super) struct WhpHypercallRegisters<'a> {
        message: hvdef::HvArm64HypercallInterceptMessage,
        pc_dirty: bool,
        gp_dirty: bool,
        _dummy: &'a (),
    }

    impl hv1_hypercall::Arm64RegisterState for &mut WhpHypercallExit<'_, '_> {
        fn pc(&mut self) -> u64 {
            self.registers.message.header.pc
        }

        fn set_pc(&mut self, pc: u64) {
            self.registers.message.header.pc = pc;
            self.registers.pc_dirty = true;
        }

        fn x(&mut self, n: u8) -> u64 {
            self.registers.message.x[n as usize]
        }

        fn set_x(&mut self, n: u8, v: u64) {
            self.registers.message.x[n as usize] = v;
            self.registers.gp_dirty = true;
        }
    }

    impl<'a, 'b> WhpHypercallExit<'a, 'b> {
        pub(super) fn reflect_to_vtl2(&mut self) {
            todo!("TODO-aarch64")
        }

        pub fn handle(
            vp: &'a mut WhpProcessor<'b>,
            message: &hvdef::HvArm64HypercallInterceptMessage,
        ) {
            let vpref = vp.vp;

            let registers = WhpHypercallRegisters {
                message: message.clone(),
                pc_dirty: false,
                gp_dirty: false,
                _dummy: &(),
            };
            let mut this = Self { vp, registers };

            WhpHypercallExit::DISPATCHER.dispatch(
                &vpref.partition.gm,
                hv1_hypercall::Arm64RegisterIo::new(&mut this, false, message.immediate == 0),
            );
            this.flush();
        }

        fn flush(&mut self) {
            let registers = &mut self.registers;
            let mut pairs = (
                ArrayVec::<_, 19>::new(),
                ArrayVec::<whp::abi::WHV_REGISTER_VALUE, 19>::new(),
            );
            if registers.gp_dirty {
                pairs.extend(registers.message.x.iter().enumerate().map(|(i, &v)| {
                    (
                        whp::abi::WHV_REGISTER_NAME(whp::abi::WHvArm64RegisterX0.0 + i as u32),
                        whp::abi::WHV_REGISTER_VALUE(v.into()),
                    )
                }));
            }
            if registers.pc_dirty {
                pairs.0.push(whp::abi::WHvArm64RegisterPc);
                pairs.1.push(registers.message.header.pc.as_abi());
            }

            let (names, values) = &pairs;
            if !names.is_empty() {
                self.vp
                    .current_whp()
                    .set_registers(names, values)
                    .expect("these registers cannot fail to set");

                registers.gp_dirty = false;
                registers.pc_dirty = false;
            }
        }
    }

    impl WhpProcessor<'_> {
        fn hypervisor_owned_reg(name: HvArm64RegisterName) -> Option<whp::abi::WHV_REGISTER_NAME> {
            match name {
                HvArm64RegisterName::GuestOsId
                | HvArm64RegisterName::Sint0
                | HvArm64RegisterName::Sint1
                | HvArm64RegisterName::Sint2
                | HvArm64RegisterName::Sint3
                | HvArm64RegisterName::Sint4
                | HvArm64RegisterName::Sint5
                | HvArm64RegisterName::Sint6
                | HvArm64RegisterName::Sint7
                | HvArm64RegisterName::Sint8
                | HvArm64RegisterName::Sint9
                | HvArm64RegisterName::Sint10
                | HvArm64RegisterName::Sint11
                | HvArm64RegisterName::Sint12
                | HvArm64RegisterName::Sint13
                | HvArm64RegisterName::Sint14
                | HvArm64RegisterName::Sint15
                | HvArm64RegisterName::Scontrol
                | HvArm64RegisterName::Sversion
                | HvArm64RegisterName::Sifp
                | HvArm64RegisterName::Sipp
                | HvArm64RegisterName::Eom
                | HvArm64RegisterName::Sirbp => Some(regs::hv_register_to_whp(name).unwrap()),
                _ => None,
            }
        }

        pub(super) fn get_vp_register(
            &mut self,
            target: RegisterTarget,
            name: HvRegisterName,
        ) -> HvResult<HvRegisterValue> {
            let _vtl = target.resolve_for_emulation(self.state.active_vtl);
            let v = match name.into() {
                HvArm64RegisterName::TimeRefCount => {
                    // TODO-aarch64: hypervisor bug. Use the hypervisor reference time once this is fixed on ARM64.
                    self.state.vmtime.now().as_100ns().into()
                }
                HvArm64RegisterName::VpIndex => self.vp.index.index().into(),
                HvArm64RegisterName::HypervisorVersion => 0u64.into(),
                HvArm64RegisterName::PrivilegesAndFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::FeaturesInfo => 0u64.into(),
                HvArm64RegisterName::ImplementationLimitsInfo => 0u64.into(),
                HvArm64RegisterName::HardwareFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::CpuManagementFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::PasidFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::SkipLevelFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::NestedVirtFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::IptFeaturesInfo => 0u64.into(),
                HvArm64RegisterName::IsolationConfiguration => 0u64.into(),
                reg => {
                    if let Some(reg) = Self::hypervisor_owned_reg(reg) {
                        let mut value = [Default::default()];
                        self.current_whp()
                            .get_registers(&[reg], &mut value)
                            .map_err(|err| {
                                err.hv_result()
                                    .map_or(HvError::InvalidParameter, HvError::from)
                            })?;
                        unsafe {
                            std::mem::transmute::<whp::abi::WHV_REGISTER_VALUE, HvRegisterValue>(
                                value[0],
                            )
                        }
                    } else {
                        tracelimit::warn_ratelimited!(name = ?reg, "unknown register name for get_vp_registers");
                        return Err(HvError::InvalidParameter);
                    }
                }
            };
            Ok(v)
        }

        pub(super) fn set_vp_register(
            &mut self,
            target: RegisterTarget,
            name: HvRegisterName,
            value: &HvRegisterValue,
        ) -> HvResult<()> {
            let _vtl = target.resolve_for_emulation(self.state.active_vtl);
            if let Some(reg) = Self::hypervisor_owned_reg(name.into()) {
                let value = unsafe {
                    std::mem::transmute::<HvRegisterValue, whp::abi::WHV_REGISTER_VALUE>(*value)
                };
                self.current_whp()
                    .set_registers(&[reg], &[value])
                    .map_err(|err| {
                        err.hv_result()
                            .map_or(HvError::InvalidParameter, HvError::from)
                    })?;

                Ok(())
            } else {
                tracelimit::warn_ratelimited!(reg = ?HvArm64RegisterName::from(name), "set register");
                Err(HvError::InvalidParameter)
            }
        }

        fn translation_registers(&self, vtl: Vtl) -> TranslationRegisters {
            let (cpsr, sctlr, tcr, ttbr0, ttbr1, syndrome) = whp::get_registers!(
                self.vp.whp(vtl),
                [
                    whp::Register64::Cpsr,
                    whp::Register64::Sctlr,
                    whp::Register64::Tcr,
                    whp::Register64::Ttbr0,
                    whp::Register64::Ttbr1,
                    whp::Register64::Syndrome,
                ]
            )
            .expect("register reads cannot fail");

            TranslationRegisters {
                cpsr: cpsr.into(),
                sctlr: sctlr.into(),
                tcr: tcr.into(),
                ttbr0,
                ttbr1,
                syndrome,
                encryption_mode: virt_support_aarch64emu::translate::EncryptionMode::None,
            }
        }
    }

    fn convert_translate_control_flags(
        control_flags: TranslateGvaControlFlagsArm64,
    ) -> Result<TranslateFlags, HvError> {
        let allowed_flags = TranslateGvaControlFlagsArm64::new()
            .with_validate_read(true)
            .with_validate_write(true)
            .with_validate_execute(true)
            .with_set_page_table_bits(true)
            .with_tlb_flush_inhibit(true)
            .with_supervisor_access(true)
            .with_user_access(true)
            .with_pan_set(true)
            .with_pan_clear(true);

        if (u64::from(control_flags) & !(u64::from(allowed_flags))) != 0 {
            tracing::trace!(
                "translate gva control flags contains flags not supported by whp {:?}",
                control_flags
            );
            return Err(HvError::InvalidParameter);
        }

        Ok(TranslateFlags::from_hv_flags(control_flags))
    }

    impl hv1_hypercall::TranslateVirtualAddressExAarch64 for WhpHypercallExit<'_, '_> {
        fn translate_virtual_address_ex(
            &mut self,
            partition_id: u64,
            vp_index: u32,
            control_flags: TranslateGvaControlFlagsArm64,
            gva_page: u64,
        ) -> HvResult<hvdef::hypercall::TranslateVirtualAddressExOutputArm64> {
            // TODO: this doesn't fully implement all the functionality of the TranslateVirtualAddressEx hypercall
            // because the underlying layers currently don't return overlay page, cache type, or event_pending.
            // Do the best we can to allow Underhill to run.
            tracing::trace!(
                ?partition_id,
                ?vp_index,
                ?control_flags,
                ?gva_page,
                "translate virtual address ex"
            );

            // Not yet supported by WHP
            if partition_id != HV_PARTITION_ID_SELF || vp_index != HV_VP_INDEX_SELF {
                return Err(HvError::InvalidParameter);
            }

            // WHP currently doesn't support the INPUT_VTL_MASK set by the Underhill instruction emulator
            if control_flags.input_vtl().target_vtl()? != Some(Vtl::Vtl0) {
                todo!("WHP can only translate gvas against VTL0");
            }

            let flags = convert_translate_control_flags(control_flags)?;

            let result = translate_gva_to_gpa(
                &self.vp.vp.partition.gm,
                gva_page * HV_PAGE_SIZE,
                &self.vp.translation_registers(Vtl::Vtl0),
                flags,
            );

            let result = match result {
                Ok(gpa) => hvdef::hypercall::TranslateVirtualAddressExOutputArm64 {
                    gpa_page: gpa / HV_PAGE_SIZE,
                    ..FromZeros::new_zeroed()
                },
                Err(err) => hvdef::hypercall::TranslateVirtualAddressExOutputArm64 {
                    translation_result: hvdef::hypercall::TranslateGvaResultExArm64 {
                        result: hvdef::hypercall::TranslateGvaResult::new()
                            .with_result_code(TranslateGvaResultCode::from(err).0),
                    },
                    ..FromZeros::new_zeroed()
                },
            };

            Ok(result)
        }
    }
}
