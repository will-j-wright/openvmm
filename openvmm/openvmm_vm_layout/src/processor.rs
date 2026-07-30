// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_arch = "x86_64")] // xtask-fmt allow-target-arch cpu-intrinsic
use anyhow::Context;
use openvmm_defs::config::ArchTopologyConfig;
use openvmm_defs::config::ProcessorTopologyConfig;
use openvmm_defs::config::X2ApicConfig;
use serde::Deserialize;
use serde::Serialize;
use vm_topology::processor::ProcessorTopology;
#[cfg(target_arch = "x86_64")] // xtask-fmt allow-target-arch cpu-intrinsic
use vm_topology::processor::TopologyBuilder;
#[cfg(target_arch = "x86_64")] // xtask-fmt allow-target-arch cpu-intrinsic
use vm_topology::processor::x86::X2ApicState;
use vm_topology::processor::x86::X86Topology;

/// Serializable x86 processor-topology inputs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct X86ProcessorTopologyPlan {
    /// Number of virtual processors.
    pub proc_count: u32,
    /// Optional logical socket size.
    pub vps_per_socket: Option<u32>,
    /// Optional SMT override.
    pub enable_smt: Option<bool>,
    /// APIC ID offset.
    pub apic_id_offset: u32,
    /// x2APIC policy.
    pub x2apic: X2ApicModePlan,
}

/// Serializable x2APIC policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum X2ApicModePlan {
    /// Use the OpenVMM automatic policy.
    Auto,
    /// Support x2APIC and enable it when required.
    Supported,
    /// Do not expose x2APIC.
    Unsupported,
    /// Enable x2APIC from reset.
    Enabled,
}

impl X86ProcessorTopologyPlan {
    /// Convert the final OpenVMM processor configuration into a serializable plan.
    pub fn from_config(config: &ProcessorTopologyConfig) -> anyhow::Result<Self> {
        let arch = match &config.arch {
            None => Default::default(),
            Some(ArchTopologyConfig::X86(arch)) => arch.clone(),
            _ => anyhow::bail!("invalid architecture config for x86 topology"),
        };

        Ok(Self {
            proc_count: config.proc_count,
            vps_per_socket: config.vps_per_socket,
            enable_smt: config.enable_smt,
            apic_id_offset: arch.apic_id_offset,
            x2apic: match arch.x2apic {
                X2ApicConfig::Auto => X2ApicModePlan::Auto,
                X2ApicConfig::Supported => X2ApicModePlan::Supported,
                X2ApicConfig::Unsupported => X2ApicModePlan::Unsupported,
                X2ApicConfig::Enabled => X2ApicModePlan::Enabled,
            },
        })
    }

    /// Resolve this plan using the same host-topology defaults as OpenVMM.
    #[cfg(target_arch = "x86_64")] // xtask-fmt allow-target-arch cpu-intrinsic
    pub fn resolve(&self) -> anyhow::Result<ProcessorTopology<X86Topology>> {
        let mut builder =
            TopologyBuilder::from_host_topology().context("querying host processor topology")?;
        builder.apic_id_offset(self.apic_id_offset);
        if let Some(smt) = self.enable_smt {
            builder.smt_enabled(smt);
        }
        if let Some(count) = self.vps_per_socket {
            builder.vps_per_socket(count);
        }
        builder.x2apic(match self.x2apic {
            X2ApicModePlan::Auto | X2ApicModePlan::Supported => X2ApicState::Supported,
            X2ApicModePlan::Unsupported => X2ApicState::Unsupported,
            X2ApicModePlan::Enabled => X2ApicState::Enabled,
        });
        builder
            .build(self.proc_count)
            .context("building x86 processor topology")
    }

    /// Reject x86 topology resolution on a non-x86 host.
    #[cfg(not(target_arch = "x86_64"))] // xtask-fmt allow-target-arch cpu-intrinsic
    pub fn resolve(&self) -> anyhow::Result<ProcessorTopology<X86Topology>> {
        anyhow::bail!("x86 processor topology can only be resolved on an x86_64 host")
    }
}

/// Resolve an OpenVMM x86 processor configuration.
#[cfg(target_arch = "x86_64")] // xtask-fmt allow-target-arch cpu-intrinsic
pub fn build_x86_topology(
    config: &ProcessorTopologyConfig,
) -> anyhow::Result<ProcessorTopology<X86Topology>> {
    X86ProcessorTopologyPlan::from_config(config)?.resolve()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_conversion_preserves_x86_topology_inputs() {
        let config = ProcessorTopologyConfig {
            proc_count: 4,
            vps_per_socket: Some(2),
            enable_smt: Some(true),
            arch: Some(ArchTopologyConfig::X86(
                openvmm_defs::config::X86TopologyConfig {
                    apic_id_offset: 16,
                    x2apic: X2ApicConfig::Enabled,
                },
            )),
        };

        assert_eq!(
            X86ProcessorTopologyPlan::from_config(&config).unwrap(),
            X86ProcessorTopologyPlan {
                proc_count: 4,
                vps_per_socket: Some(2),
                enable_smt: Some(true),
                apic_id_offset: 16,
                x2apic: X2ApicModePlan::Enabled,
            }
        );
    }
}
