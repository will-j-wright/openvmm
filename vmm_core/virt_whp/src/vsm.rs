// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use hv1_structs::VtlSet;
use hvdef::HV_PAGE_SIZE;
use hvdef::HvError;
use hvdef::HvMapGpaFlags;
use hvdef::HvRegisterGuestVsmPartitionConfig;
use hvdef::HvRegisterVsmPartitionConfig;
use hvdef::Vtl;
use hvdef::hypercall::AcceptPagesAttributes;
use hvdef::hypercall::HostVisibilityType;
use hvdef::hypercall::VtlPermissionSet;
use inspect::Inspect;
use thiserror::Error;
use virt::IsolationType;
use virt::VpIndex;

/// WHP VSM controller state.
#[derive(Inspect)]
pub(crate) struct VsmController {
    #[inspect(flatten)]
    mode: VsmMode,
    state: VtlState,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct VsmPartitionConfigWrite {
    vp_index: VpIndex,
    target_vtl: Vtl,
    value: u64,
}

impl VsmPartitionConfigWrite {
    pub(crate) fn vp_index(self) -> VpIndex {
        self.vp_index
    }

    pub(crate) fn target_vtl(self) -> Vtl {
        self.target_vtl
    }

    pub(crate) fn value(self) -> u64 {
        self.value
    }
}

#[derive(Inspect)]
#[inspect(external_tag)]
enum VsmMode {
    Disabled,
    LegacyVtl2Compatibility,
    Whp,
}

#[derive(Inspect)]
struct VtlState {
    #[inspect(with = "|x| *x as u8")]
    max_vtl: Vtl,
    partition_vtls: VtlSet,
    #[inspect(skip)]
    vp_vtls: Vec<VtlSet>,
    #[inspect(skip)]
    vsm_partition_configs: [u64; 3],
}

#[derive(Error, Debug)]
pub enum VsmError {
    #[error("VSM requires a maximum VTL above VTL0")]
    Vtl0Only,
    #[cfg(not(guest_arch = "x86_64"))]
    #[error("VSM is currently only supported for x64 guests")]
    UnsupportedArchitecture,
    #[error("VSM is incompatible with isolated partitions in this prototype")]
    IncompatibleWithIsolation,
    #[error("the host does not support the WHP VSM APIs")]
    HostUnsupported,
    #[error("updated WHP Guest VSM host support with WHvStartVirtualProcessor is required")]
    StartVirtualProcessorHostUnsupported,
    #[error("VSM is not enabled")]
    VsmDisabled,
    #[error("VSM target {vtl:?} is not enabled")]
    VtlNotEnabled { vtl: Vtl },
    #[error("VSM target VTL0 is invalid for this operation")]
    InvalidTargetVtl0,
    #[error("invalid VP index {0}")]
    InvalidVpIndex(u32),
    #[error("VSM VP {vp_index} {vtl:?} is already enabled")]
    VpVtlAlreadyEnabled { vp_index: u32, vtl: Vtl },
    #[error("VSM VP {vp_index} target {vtl:?} is not enabled")]
    VpVtlNotEnabled { vp_index: u32, vtl: Vtl },
    #[error("VSM register is not valid for target {vtl:?}")]
    InvalidRegisterVtl { vtl: Vtl },
    #[error("invalid VSM register value")]
    InvalidRegisterValue,
    #[error("VSM reported invalid active VTL {vtl}")]
    InvalidActiveVtl { vtl: u8 },
    #[error("VSM map flags {flags:#x} cannot be represented by WHP VTL protection APIs")]
    UnsupportedMapFlags { flags: u32 },
    #[error("unsupported VSM sparse GPA host visibility {visibility:?}")]
    UnsupportedHostVisibility { visibility: HostVisibilityType },
    #[error("GPA page {gpa_page:#x} overflows a byte address")]
    GpaPageOverflow { gpa_page: u64 },
    #[error("VSM WHP operation processed {processed} pages out of {requested}")]
    ShortOperation { processed: usize, requested: usize },
    #[error("VSM WHP operation timed out")]
    WhpTimeout(#[source] whp::WHvError),
    #[error("updated WHP Guest VSM host support required")]
    GuestVsmHostSupportRequired(#[source] whp::WHvError),
    #[error("VSM WHP operation failed after processing {processed} pages")]
    WhpOperation {
        #[source]
        source: whp::WHvError,
        processed: usize,
    },
    #[error("VSM WHP operation failed")]
    Whp(#[from] whp::WHvError),
}

impl VsmError {
    pub(crate) fn completed_pages(&self) -> usize {
        match self {
            VsmError::ShortOperation { processed, .. }
            | VsmError::WhpOperation { processed, .. } => *processed,
            _ => 0,
        }
    }

    pub(crate) fn whp_error(&self) -> Option<&whp::WHvError> {
        match self {
            VsmError::WhpTimeout(error)
            | VsmError::GuestVsmHostSupportRequired(error)
            | VsmError::Whp(error) => Some(error),
            VsmError::WhpOperation { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<whp::WHvOperationError> for VsmError {
    fn from(error: whp::WHvOperationError) -> Self {
        let (source, processed) = error.into_parts();
        Self::WhpOperation {
            source,
            processed: completed_pages(processed),
        }
    }
}

pub(crate) fn vsm_partition_config_whp_error(error: whp::WHvError) -> VsmError {
    if error.is_timeout() {
        VsmError::WhpTimeout(error)
    } else if error
        .hv_result()
        .is_some_and(|result| HvError::from(result) == HvError::UnknownRegisterName)
    {
        VsmError::GuestVsmHostSupportRequired(error)
    } else {
        VsmError::Whp(error)
    }
}

fn vtl0_set() -> VtlSet {
    let mut vtls = VtlSet::new();
    vtls.set(Vtl::Vtl0);
    vtls
}

fn vtl_state(max_vtl: Vtl, vp_count: u32) -> VtlState {
    VtlState {
        max_vtl,
        partition_vtls: vtl0_set(),
        vp_vtls: vec![vtl0_set(); vp_count as usize],
        vsm_partition_configs: [0; 3],
    }
}

fn configured_vtls(max_vtl: Vtl) -> impl Iterator<Item = Vtl> {
    [Vtl::Vtl1, Vtl::Vtl2]
        .into_iter()
        .filter(move |&vtl| vtl <= max_vtl)
}

fn whp_vtl(vtl: Vtl) -> whp::abi::WHV_VTL {
    vtl.into()
}

fn vtl_bit(vtl: Vtl) -> u16 {
    1 << u8::from(vtl)
}

fn vtl_set_bits(vtls: &VtlSet) -> u16 {
    [Vtl::Vtl0, Vtl::Vtl1, Vtl::Vtl2]
        .into_iter()
        .filter(|&vtl| vtls.is_set(vtl))
        .fold(0, |bits, vtl| bits | vtl_bit(vtl))
}

fn checked_gpa_page_to_address(gpa_page: u64) -> Result<u64, VsmError> {
    gpa_page
        .checked_mul(HV_PAGE_SIZE)
        .ok_or(VsmError::GpaPageOverflow { gpa_page })
}

fn gpa_pages_to_addresses(gpa_pages: &[u64]) -> Result<Vec<u64>, VsmError> {
    gpa_pages
        .iter()
        .map(|&gpa_page| checked_gpa_page_to_address(gpa_page))
        .collect()
}

fn whp_map_gpa_flags(
    map_flags: HvMapGpaFlags,
) -> Result<whp::abi::WHV_MAP_GPA_RANGE_FLAGS, VsmError> {
    let raw_flags = u32::from(map_flags);
    let representable = HvMapGpaFlags::new()
        .with_readable(true)
        .with_writable(true)
        .with_kernel_executable(true)
        .with_user_executable(true);
    let known = representable
        .with_supervisor_shadow_stack(true)
        .with_paging_writability(true)
        .with_verify_paging_writability(true)
        .with_adjustable(true);

    if raw_flags & !u32::from(known) != 0
        || map_flags.supervisor_shadow_stack()
        || map_flags.paging_writability()
        || map_flags.verify_paging_writability()
        || map_flags.adjustable()
        || map_flags.kernel_executable() != map_flags.user_executable()
    {
        return Err(VsmError::UnsupportedMapFlags { flags: raw_flags });
    }

    let mut flags = whp::abi::WHvMapGpaRangeFlagNone;
    if map_flags.readable() {
        flags |= whp::abi::WHvMapGpaRangeFlagRead;
    }
    if map_flags.writable() {
        flags |= whp::abi::WHvMapGpaRangeFlagWrite;
    }
    if map_flags.kernel_executable() || map_flags.user_executable() {
        flags |= whp::abi::WHvMapGpaRangeFlagExecute;
    }

    Ok(flags)
}

fn whp_vtl_permission_set(permissions: VtlPermissionSet) -> whp::abi::WHV_VTL_PERMISSION_SET {
    whp::abi::WHV_VTL_PERMISSION_SET {
        VtlPermissionFrom1: permissions.vtl_permission_from_1,
    }
}

fn completed_pages(processed: u64) -> usize {
    usize::try_from(processed).unwrap_or(usize::MAX)
}

fn ensure_all_pages_processed(processed: u64, requested: usize) -> Result<(), VsmError> {
    if processed == requested as u64 {
        Ok(())
    } else {
        Err(VsmError::ShortOperation {
            processed: completed_pages(processed),
            requested,
        })
    }
}

impl VsmController {
    pub(crate) fn new(
        config: Option<&virt::VsmConfig>,
        legacy_vtl2: bool,
        vp_count: u32,
        isolation: IsolationType,
    ) -> Result<Self, VsmError> {
        let Some(config) = config else {
            return Ok(Self {
                mode: VsmMode::Disabled,
                state: vtl_state(Vtl::Vtl0, vp_count),
            });
        };

        if config.max_vtl == Vtl::Vtl0 {
            return Err(VsmError::Vtl0Only);
        }

        if legacy_vtl2 {
            return Ok(Self {
                mode: VsmMode::LegacyVtl2Compatibility,
                state: vtl_state(config.max_vtl, vp_count),
            });
        }

        if isolation.is_isolated() {
            return Err(VsmError::IncompatibleWithIsolation);
        }

        #[cfg(not(guest_arch = "x86_64"))]
        {
            return Err(VsmError::UnsupportedArchitecture);
        }

        if !whp::capabilities::start_virtual_processor() {
            return Err(VsmError::StartVirtualProcessorHostUnsupported);
        }

        if !whp::capabilities::vsm() {
            return Err(VsmError::HostUnsupported);
        }

        Ok(Self {
            mode: VsmMode::Whp,
            state: vtl_state(config.max_vtl, vp_count),
        })
    }

    pub(crate) fn is_whp(&self) -> bool {
        matches!(self.mode, VsmMode::Whp)
    }

    pub(crate) fn max_vtl(&self) -> Vtl {
        self.state.max_vtl
    }

    pub(crate) fn is_partition_vtl_enabled(&self, vtl: Vtl) -> bool {
        self.state.partition_vtls.is_set(vtl)
    }

    #[cfg(test)]
    fn vp_enabled_vtl_bits(&self, vp_index: VpIndex) -> Result<u16, VsmError> {
        self.validate_vp_index(vp_index)?;
        Ok(vtl_set_bits(&self.state.vp_vtls[vp_index.index() as usize]))
    }

    pub(crate) fn validate_vp_vtl_enabled(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        self.validate_vp_index(vp_index)?;

        if vtl > self.state.max_vtl || !self.is_partition_vtl_enabled(vtl) {
            return Err(VsmError::VtlNotEnabled { vtl });
        }

        let vp_vtls = &self.state.vp_vtls[vp_index.index() as usize];

        if !vp_vtls.is_set(vtl) {
            return Err(VsmError::VpVtlNotEnabled {
                vp_index: vp_index.index(),
                vtl,
            });
        }

        Ok(())
    }

    fn validate_vp_index(&self, vp_index: VpIndex) -> Result<(), VsmError> {
        if self.state.vp_vtls.get(vp_index.index() as usize).is_none() {
            return Err(VsmError::InvalidVpIndex(vp_index.index()));
        }

        Ok(())
    }

    fn validate_vsm_register_vtl(&self, vp_index: VpIndex, vtl: Vtl) -> Result<(), VsmError> {
        self.validate_vp_index(vp_index)?;
        if vtl == Vtl::Vtl0 {
            return Err(VsmError::InvalidRegisterVtl { vtl });
        }
        if vtl > self.state.max_vtl || !self.is_partition_vtl_enabled(vtl) {
            return Err(VsmError::VtlNotEnabled { vtl });
        }

        Ok(())
    }

    pub(crate) fn partition_enabled_vtl_bits(&self) -> Result<u16, VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        Ok(vtl_set_bits(&self.state.partition_vtls))
    }

    pub(crate) fn vsm_partition_config(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<HvRegisterVsmPartitionConfig, VsmError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;
        Ok(HvRegisterVsmPartitionConfig::from(
            self.state.vsm_partition_configs[vtl as usize],
        ))
    }

    pub(crate) fn prepare_vsm_partition_config_write(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
        config: HvRegisterVsmPartitionConfig,
    ) -> Result<VsmPartitionConfigWrite, VsmError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;
        if vtl != Vtl::Vtl1 {
            return Err(VsmError::InvalidRegisterVtl { vtl });
        }
        if config.reserved() != 0 {
            return Err(VsmError::InvalidRegisterValue);
        }

        Ok(VsmPartitionConfigWrite {
            vp_index,
            target_vtl: vtl,
            value: config.into(),
        })
    }

    pub(crate) fn complete_vsm_partition_config_write(
        &mut self,
        write: VsmPartitionConfigWrite,
        whp_result: Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        whp_result?;
        self.state.vsm_partition_configs[write.target_vtl as usize] = write.value;
        Ok(())
    }

    pub(crate) fn guest_vsm_partition_config(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<HvRegisterGuestVsmPartitionConfig, VsmError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;
        Ok(HvRegisterGuestVsmPartitionConfig::new().with_maximum_vtl(u8::from(self.max_vtl())))
    }

    pub(crate) fn validate_guest_vsm_partition_config(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
        config: HvRegisterGuestVsmPartitionConfig,
    ) -> Result<(), VsmError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;

        let allowed_bits = HvRegisterGuestVsmPartitionConfig::new().with_maximum_vtl(0xf);
        if u64::from(config) & !u64::from(allowed_bits) != 0
            || config.maximum_vtl() > u8::from(self.max_vtl())
        {
            return Err(VsmError::InvalidRegisterValue);
        }

        Ok(())
    }

    pub(crate) fn set_partition_properties_before_setup(
        &self,
        partition: &mut whp::PartitionConfig,
    ) -> Result<(), whp::WHvError> {
        if !self.is_whp() {
            return Ok(());
        }

        for vtl in configured_vtls(self.state.max_vtl) {
            match vtl {
                Vtl::Vtl0 => {}
                Vtl::Vtl1 => {
                    partition.set_property(whp::PartitionProperty::Vtl1(true))?;
                }
                Vtl::Vtl2 => {
                    partition.set_property(whp::PartitionProperty::Vtl2(true))?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn enable_partition_vtls_after_setup(
        &mut self,
        partition: &whp::Partition,
    ) -> Result<(), whp::WHvError> {
        if !self.is_whp() {
            return Ok(());
        }

        for vtl in configured_vtls(self.state.max_vtl) {
            partition.enable_partition_vtl(
                whp_vtl(vtl),
                whp::abi::WHV_ENABLE_PARTITION_VTL_FLAGS::default(),
            )?;
            self.state.partition_vtls.set(vtl);
        }

        Ok(())
    }

    pub(crate) fn enable_vp_vtl(
        &mut self,
        partition: &whp::Partition,
        vp_index: VpIndex,
        vtl: Vtl,
        initial_context: &whp::abi::WHV_INITIAL_VP_CONTEXT,
    ) -> Result<(), VsmError> {
        if !self.is_whp()
            || vtl == Vtl::Vtl0
            || vtl > self.state.max_vtl
            || !self.state.partition_vtls.is_set(vtl)
        {
            return Err(VsmError::VtlNotEnabled { vtl });
        }

        let Some(vp_vtls) = self.state.vp_vtls.get_mut(vp_index.index() as usize) else {
            return Err(VsmError::InvalidVpIndex(vp_index.index()));
        };

        if vp_vtls.is_set(vtl) {
            return Err(VsmError::VpVtlAlreadyEnabled {
                vp_index: vp_index.index(),
                vtl,
            });
        }

        partition.enable_vp_vtl(vp_index.index(), whp_vtl(vtl), initial_context)?;
        vp_vtls.set(vtl);
        Ok(())
    }

    pub(crate) fn input_vtl(&self, target_vtl: Option<Vtl>) -> whp::abi::WHV_INPUT_VTL {
        match target_vtl {
            Some(target_vtl) => whp::abi::WHV_INPUT_VTL::target(whp_vtl(target_vtl)),
            None => whp::abi::WHV_INPUT_VTL::current(),
        }
    }

    fn protection_input_vtl(
        &self,
        target_vtl: Option<Vtl>,
    ) -> Result<whp::abi::WHV_INPUT_VTL, VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        if let Some(target_vtl) = target_vtl {
            if target_vtl == Vtl::Vtl0 {
                return Err(VsmError::InvalidTargetVtl0);
            }
            if target_vtl > self.state.max_vtl || !self.state.partition_vtls.is_set(target_vtl) {
                return Err(VsmError::VtlNotEnabled { vtl: target_vtl });
            }
        }

        Ok(self.input_vtl(target_vtl))
    }

    pub(crate) fn modify_vtl_protection_mask(
        &self,
        partition: &whp::Partition,
        vp_index: VpIndex,
        map_flags: HvMapGpaFlags,
        target_vtl: Option<Vtl>,
        gpa_pages: &[u64],
    ) -> Result<usize, VsmError> {
        let input_vtl = self.protection_input_vtl(target_vtl)?;
        let map_flags = whp_map_gpa_flags(map_flags)?;
        let guest_addresses = gpa_pages_to_addresses(gpa_pages)?;
        let processed = partition.modify_vtl_protection_mask(
            vp_index.index(),
            map_flags,
            &guest_addresses,
            input_vtl,
        )?;
        ensure_all_pages_processed(processed, gpa_pages.len())?;
        Ok(completed_pages(processed))
    }

    pub(crate) fn modify_vtl_protection_mask_range(
        &self,
        partition: &whp::Partition,
        gpa_page_base: u64,
        vtl_set: u16,
        permissions: VtlPermissionSet,
        page_count: usize,
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        let guest_address = checked_gpa_page_to_address(gpa_page_base)?;
        let permissions = vec![whp_vtl_permission_set(permissions); page_count];
        let processed =
            partition.modify_vtl_protection_mask_range(guest_address, vtl_set, &permissions)?;
        ensure_all_pages_processed(processed, page_count)
    }

    #[expect(dead_code)]
    pub(crate) fn query_vtl_protection_mask_range(
        &self,
        partition: &whp::Partition,
        gpa_page_base: u64,
        vtl_set: u16,
        permissions: &mut [whp::abi::WHV_VTL_PERMISSION_SET],
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        let guest_address = checked_gpa_page_to_address(gpa_page_base)?;
        let processed =
            partition.query_vtl_protection_mask_range(guest_address, vtl_set, permissions)?;
        ensure_all_pages_processed(processed, permissions.len())
    }

    pub(crate) fn modify_sparse_gpa_page_host_visibility(
        &self,
        partition: &whp::Partition,
        visibility: HostVisibilityType,
        gpa_pages: &[u64],
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        let host_access = whp::abi::WHvMapGpaRangeFlagRead | whp::abi::WHvMapGpaRangeFlagWrite;
        let guest_addresses = gpa_pages_to_addresses(gpa_pages)?;
        let processed = match visibility {
            HostVisibilityType::PRIVATE => {
                partition.release_sparse_gpa_page_host_access(host_access, &guest_addresses)?
            }
            HostVisibilityType::SHARED => {
                partition.acquire_sparse_gpa_page_host_access(host_access, &guest_addresses)?
            }
            _ => return Err(VsmError::UnsupportedHostVisibility { visibility }),
        };

        ensure_all_pages_processed(processed, gpa_pages.len())
    }

    pub(crate) fn accept_gpa_pages_no_security_shim(
        &self,
        partition: &whp::Partition,
        page_attributes: AcceptPagesAttributes,
        vtl_permission_set: VtlPermissionSet,
        gpa_page_base: u64,
        page_count: usize,
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }

        let gpa_pages = (0..page_count)
            .map(|page| {
                gpa_page_base
                    .checked_add(page as u64)
                    .ok_or(VsmError::GpaPageOverflow {
                        gpa_page: gpa_page_base,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.modify_sparse_gpa_page_host_visibility(
            partition,
            page_attributes.host_visibility(),
            &gpa_pages,
        )?;

        let vtl_set = page_attributes.vtl_set();
        if vtl_set != 0 {
            self.modify_vtl_protection_mask_range(
                partition,
                gpa_page_base,
                vtl_set as u16,
                vtl_permission_set,
                page_count,
            )?;
        }

        // This compatibility path does not provide memory isolation: GuestMemory
        // remains shared and devices can still DMA to these pages.
        Ok(())
    }

    pub(crate) fn get_vp_registers(
        &self,
        vp_index: VpIndex,
        vp: whp::Processor<'_>,
        target_vtl: Option<Vtl>,
        names: &[whp::abi::WHV_REGISTER_NAME],
        values: &mut [whp::abi::WHV_REGISTER_VALUE],
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }
        self.validate_vp_index(vp_index)?;
        if let Some(target_vtl) = target_vtl {
            if target_vtl > self.state.max_vtl || !self.is_partition_vtl_enabled(target_vtl) {
                return Err(VsmError::VtlNotEnabled { vtl: target_vtl });
            }
        }
        vp.get_registers_for_vtl(self.input_vtl(target_vtl), names, values)?;
        Ok(())
    }

    pub(crate) fn set_vp_registers(
        &self,
        vp_index: VpIndex,
        vp: whp::Processor<'_>,
        target_vtl: Option<Vtl>,
        names: &[whp::abi::WHV_REGISTER_NAME],
        values: &[whp::abi::WHV_REGISTER_VALUE],
    ) -> Result<(), VsmError> {
        if !self.is_whp() {
            return Err(VsmError::VsmDisabled);
        }
        self.validate_vp_index(vp_index)?;
        if let Some(target_vtl) = target_vtl {
            if target_vtl > self.state.max_vtl || !self.is_partition_vtl_enabled(target_vtl) {
                return Err(VsmError::VtlNotEnabled { vtl: target_vtl });
            }
        }
        vp.set_registers_for_vtl(self.input_vtl(target_vtl), names, values)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use test_with_tracing::test;

    fn whp_vsm_controller(max_vtl: Vtl, vp_count: u32) -> VsmController {
        VsmController {
            mode: VsmMode::Whp,
            state: vtl_state(max_vtl, vp_count),
        }
    }

    fn enable_partition_vtl(controller: &mut VsmController, vtl: Vtl) {
        controller.state.partition_vtls.set(vtl);
    }

    #[test]
    fn configured_vtls_are_vtl_generic() {
        assert_eq!(configured_vtls(Vtl::Vtl1).collect::<Vec<_>>(), [Vtl::Vtl1]);
        assert_eq!(
            configured_vtls(Vtl::Vtl2).collect::<Vec<_>>(),
            [Vtl::Vtl1, Vtl::Vtl2]
        );
    }

    #[test]
    fn whp_vsm_configuration_overrides_legacy_vtl2() {
        assert!(crate::use_legacy_vtl2(false, true));
        assert!(!crate::use_legacy_vtl2(true, true));
        assert!(!crate::use_legacy_vtl2(true, false));
        assert!(!crate::use_legacy_vtl2(false, false));
    }

    #[test]
    fn protection_gpfns_convert_to_byte_gpas_without_reordering() {
        assert_eq!(
            gpa_pages_to_addresses(&[0x123, 0x124, 0x200]).unwrap(),
            [0x123000, 0x124000, 0x200000]
        );
    }

    #[test]
    fn whp_vsm_state_tracks_enabled_vtls_generically() {
        let mut controller = whp_vsm_controller(Vtl::Vtl2, 2);
        let vp_index = VpIndex::new(1);

        assert_eq!(controller.vp_enabled_vtl_bits(vp_index).unwrap(), 1);
        assert!(matches!(
            controller.validate_vp_vtl_enabled(vp_index, Vtl::Vtl1),
            Err(VsmError::VtlNotEnabled { vtl: Vtl::Vtl1 })
        ));

        for vtl in configured_vtls(controller.max_vtl()) {
            controller.state.partition_vtls.set(vtl);
            controller.state.vp_vtls[vp_index.index() as usize].set(vtl);
        }

        for vtl in [Vtl::Vtl0, Vtl::Vtl1, Vtl::Vtl2] {
            controller.validate_vp_vtl_enabled(vp_index, vtl).unwrap();
        }

        assert_eq!(controller.vp_enabled_vtl_bits(vp_index).unwrap(), 0b111);
        assert_eq!(controller.input_vtl(None).0, 0);
        assert_eq!(controller.input_vtl(Some(Vtl::Vtl1)).0, 0x11);
        assert_eq!(controller.input_vtl(Some(Vtl::Vtl2)).0, 0x12);
    }

    #[test]
    fn vsm_partition_config_cache_commits_only_after_success() {
        let controller = Mutex::new(whp_vsm_controller(Vtl::Vtl1, 1));
        enable_partition_vtl(&mut controller.lock(), Vtl::Vtl1);
        let config = HvRegisterVsmPartitionConfig::from(0x7f);
        let write = controller
            .lock()
            .prepare_vsm_partition_config_write(VpIndex::new(0), Vtl::Vtl1, config)
            .unwrap();

        assert_eq!(
            u64::from(
                controller
                    .lock()
                    .vsm_partition_config(VpIndex::new(0), Vtl::Vtl1)
                    .unwrap()
            ),
            0
        );

        controller
            .lock()
            .complete_vsm_partition_config_write(write, Ok(()))
            .unwrap();

        assert_eq!(
            u64::from(
                controller
                    .lock()
                    .vsm_partition_config(VpIndex::new(0), Vtl::Vtl1)
                    .unwrap()
            ),
            0x7f
        );
    }

    #[test]
    fn vsm_partition_config_timeout_does_not_commit_cache() {
        let controller = Mutex::new(whp_vsm_controller(Vtl::Vtl1, 1));
        enable_partition_vtl(&mut controller.lock(), Vtl::Vtl1);
        let write = controller
            .lock()
            .prepare_vsm_partition_config_write(
                VpIndex::new(0),
                Vtl::Vtl1,
                HvRegisterVsmPartitionConfig::from(0x7f),
            )
            .unwrap();
        let timeout = whp::WHvError::from_hresult(0x80350078_u32 as i32).expect("nonzero HRESULT");
        let error = vsm_partition_config_whp_error(timeout);

        assert!(matches!(error, VsmError::WhpTimeout(_)));
        assert!(matches!(
            controller
                .lock()
                .complete_vsm_partition_config_write(write, Err(error)),
            Err(VsmError::WhpTimeout(_))
        ));
        assert_eq!(
            u64::from(
                controller
                    .lock()
                    .vsm_partition_config(VpIndex::new(0), Vtl::Vtl1)
                    .unwrap()
            ),
            0
        );
    }

    #[test]
    fn vsm_partition_config_permanent_failure_does_not_commit_cache() {
        let controller = Mutex::new(whp_vsm_controller(Vtl::Vtl1, 1));
        enable_partition_vtl(&mut controller.lock(), Vtl::Vtl1);
        let write = controller
            .lock()
            .prepare_vsm_partition_config_write(
                VpIndex::new(0),
                Vtl::Vtl1,
                HvRegisterVsmPartitionConfig::from(0x7f),
            )
            .unwrap();
        let failure = whp::WHvError::from_hresult(0x80004005_u32 as i32).expect("nonzero HRESULT");
        let error = vsm_partition_config_whp_error(failure);

        assert!(matches!(error, VsmError::Whp(_)));
        assert!(matches!(
            controller
                .lock()
                .complete_vsm_partition_config_write(write, Err(error)),
            Err(VsmError::Whp(_))
        ));
        assert_eq!(
            u64::from(
                controller
                    .lock()
                    .vsm_partition_config(VpIndex::new(0), Vtl::Vtl1)
                    .unwrap()
            ),
            0
        );
    }

    #[test]
    fn unknown_vsm_partition_config_register_requires_updated_host() {
        let unknown_register =
            whp::WHvError::from_hresult(0x80350087_u32 as i32).expect("nonzero HRESULT");

        assert!(matches!(
            vsm_partition_config_whp_error(unknown_register),
            VsmError::GuestVsmHostSupportRequired(_)
        ));
    }

    #[test]
    fn whp_vsm_protection_current_target_uses_whp_current_vtl() {
        let controller = whp_vsm_controller(Vtl::Vtl1, 1);

        assert_eq!(
            controller.protection_input_vtl(None).unwrap(),
            whp::abi::WHV_INPUT_VTL::current()
        );
    }

    #[test]
    fn whp_vsm_protection_explicit_vtl1_does_not_require_software_active_vtl() {
        let mut controller = whp_vsm_controller(Vtl::Vtl1, 1);
        enable_partition_vtl(&mut controller, Vtl::Vtl1);

        assert_eq!(
            controller.protection_input_vtl(Some(Vtl::Vtl1)).unwrap(),
            whp::abi::WHV_INPUT_VTL::target(1)
        );
    }

    #[test]
    fn whp_vsm_protection_rejects_vtl0_and_disabled_vtl() {
        let controller = whp_vsm_controller(Vtl::Vtl1, 1);

        assert!(matches!(
            controller.protection_input_vtl(Some(Vtl::Vtl0)),
            Err(VsmError::InvalidTargetVtl0)
        ));
        assert!(matches!(
            controller.protection_input_vtl(Some(Vtl::Vtl1)),
            Err(VsmError::VtlNotEnabled { vtl: Vtl::Vtl1 })
        ));
    }
}
