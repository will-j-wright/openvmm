// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::VsmError;
use hv1_structs::VtlSet;
use hvdef::HvRegisterGuestVsmPartitionConfig;
use hvdef::HvRegisterVsmPartitionConfig;
use hvdef::Vtl;
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

#[derive(Debug, Error)]
pub(crate) enum EnableVpVtlError {
    #[error("WHP VSM is not enabled for {vtl:?}")]
    NotEnabled { vtl: Vtl },
    #[error("invalid VP index {0}")]
    InvalidVpIndex(u32),
    #[error("WHP VSM VP {vp_index} {vtl:?} is already enabled")]
    AlreadyEnabled { vp_index: u32, vtl: Vtl },
    #[error("failed to enable WHP VSM VP VTL")]
    Whp(#[from] whp::WHvError),
}

#[derive(Debug, Error)]
pub(crate) enum VpVtlAccessError {
    #[error("WHP VSM is not enabled")]
    WhpDisabled,
    #[error("WHP VSM target {vtl:?} is not enabled")]
    VtlNotEnabled { vtl: Vtl },
    #[error("invalid VP index {0}")]
    InvalidVpIndex(u32),
    #[error("WHP VSM VP {vp_index} target {vtl:?} is not enabled")]
    VpVtlNotEnabled { vp_index: u32, vtl: Vtl },
    #[error("WHP VSM register is not valid for target {vtl:?}")]
    InvalidRegisterVtl { vtl: Vtl },
    #[error("invalid WHP VSM register value")]
    InvalidRegisterValue,
}

#[derive(Debug, Error)]
pub(crate) enum RegisterAccessError {
    #[error(transparent)]
    Access(#[from] VpVtlAccessError),
    #[error("failed to access WHP VSM VP registers")]
    Whp(#[from] whp::WHvError),
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

    pub(crate) fn is_vp_vtl_enabled(&self, vp_index: VpIndex, vtl: Vtl) -> bool {
        self.state
            .vp_vtls
            .get(vp_index.index() as usize)
            .is_some_and(|vtls| vtls.is_set(vtl))
    }

    pub(crate) fn vp_enabled_vtl_bits(&self, vp_index: VpIndex) -> Result<u16, VpVtlAccessError> {
        if !self.is_whp() {
            return Err(VpVtlAccessError::WhpDisabled);
        }

        let Some(vp_vtls) = self.state.vp_vtls.get(vp_index.index() as usize) else {
            return Err(VpVtlAccessError::InvalidVpIndex(vp_index.index()));
        };

        Ok(vtl_set_bits(vp_vtls))
    }

    pub(crate) fn validate_vp_vtl_enabled(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<(), VpVtlAccessError> {
        if !self.is_whp() {
            return Err(VpVtlAccessError::WhpDisabled);
        }

        if vtl > self.state.max_vtl || !self.is_partition_vtl_enabled(vtl) {
            return Err(VpVtlAccessError::VtlNotEnabled { vtl });
        }

        let Some(vp_vtls) = self.state.vp_vtls.get(vp_index.index() as usize) else {
            return Err(VpVtlAccessError::InvalidVpIndex(vp_index.index()));
        };

        if !vp_vtls.is_set(vtl) {
            return Err(VpVtlAccessError::VpVtlNotEnabled {
                vp_index: vp_index.index(),
                vtl,
            });
        }

        Ok(())
    }

    fn validate_vsm_register_vtl(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<(), VpVtlAccessError> {
        self.validate_vp_vtl_enabled(vp_index, vtl)?;
        if vtl == Vtl::Vtl0 {
            return Err(VpVtlAccessError::InvalidRegisterVtl { vtl });
        }

        Ok(())
    }

    pub(crate) fn vsm_partition_config(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<HvRegisterVsmPartitionConfig, VpVtlAccessError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;
        Ok(HvRegisterVsmPartitionConfig::from(
            self.state.vsm_partition_configs[vtl as usize],
        ))
    }

    pub(crate) fn set_vsm_partition_config(
        &mut self,
        vp_index: VpIndex,
        vtl: Vtl,
        config: HvRegisterVsmPartitionConfig,
    ) -> Result<(), VpVtlAccessError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;
        self.state.vsm_partition_configs[vtl as usize] = u64::from(config);
        Ok(())
    }

    pub(crate) fn guest_vsm_partition_config(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
    ) -> Result<HvRegisterGuestVsmPartitionConfig, VpVtlAccessError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;
        Ok(HvRegisterGuestVsmPartitionConfig::new().with_maximum_vtl(u8::from(self.max_vtl())))
    }

    pub(crate) fn validate_guest_vsm_partition_config(
        &self,
        vp_index: VpIndex,
        vtl: Vtl,
        config: HvRegisterGuestVsmPartitionConfig,
    ) -> Result<(), VpVtlAccessError> {
        self.validate_vsm_register_vtl(vp_index, vtl)?;

        let allowed_bits = HvRegisterGuestVsmPartitionConfig::new().with_maximum_vtl(0xf);
        if u64::from(config) & !u64::from(allowed_bits) != 0
            || config.maximum_vtl() > u8::from(self.max_vtl())
        {
            return Err(VpVtlAccessError::InvalidRegisterValue);
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
    ) -> Result<(), EnableVpVtlError> {
        if !self.is_whp()
            || vtl == Vtl::Vtl0
            || vtl > self.state.max_vtl
            || !self.state.partition_vtls.is_set(vtl)
        {
            return Err(EnableVpVtlError::NotEnabled { vtl });
        }

        let Some(vp_vtls) = self.state.vp_vtls.get_mut(vp_index.index() as usize) else {
            return Err(EnableVpVtlError::InvalidVpIndex(vp_index.index()));
        };

        if vp_vtls.is_set(vtl) {
            return Err(EnableVpVtlError::AlreadyEnabled {
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

    pub(crate) fn get_vp_registers(
        &self,
        vp_index: VpIndex,
        vp: whp::Processor<'_>,
        target_vtl: Vtl,
        names: &[whp::abi::WHV_REGISTER_NAME],
        values: &mut [whp::abi::WHV_REGISTER_VALUE],
    ) -> Result<(), RegisterAccessError> {
        self.validate_vp_vtl_enabled(vp_index, target_vtl)?;
        vp.get_registers_for_vtl(self.input_vtl(Some(target_vtl)), names, values)?;
        Ok(())
    }

    pub(crate) fn set_vp_registers(
        &self,
        vp_index: VpIndex,
        vp: whp::Processor<'_>,
        target_vtl: Vtl,
        names: &[whp::abi::WHV_REGISTER_NAME],
        values: &[whp::abi::WHV_REGISTER_VALUE],
    ) -> Result<(), RegisterAccessError> {
        self.validate_vp_vtl_enabled(vp_index, target_vtl)?;
        vp.set_registers_for_vtl(self.input_vtl(Some(target_vtl)), names, values)?;
        Ok(())
    }

    #[expect(dead_code)]
    pub(crate) fn active_vtl_after_exit(&self, vp_index: VpIndex, exit_vtl: Option<Vtl>) -> Vtl {
        exit_vtl
            .filter(|&vtl| self.is_vp_vtl_enabled(vp_index, vtl))
            .unwrap_or(Vtl::Vtl0)
    }
}
