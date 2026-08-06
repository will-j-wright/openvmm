// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Configuration for generating IGVM files. These are deserialized from a JSON
//! manifest file used by the file builder.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

use openvmm_vm_layout::VmLayoutPlan;
use openvmm_vm_layout::X86ProcessorTopologyPlan;
use product_policy::ProductPolicy;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::PathBuf;

const IGVM_PAGE_SIZE_BYTES: u64 = 4096;
const X64_PAGE_TABLE_ADDRESS_BIT_RANGE: std::ops::RangeInclusive<u8> = 32..=51;

/// The UEFI config type to pass to the UEFI loader.
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum UefiConfigType {
    /// No UEFI config set at load time.
    None,
    /// UEFI config is specified via IGVM parameters.
    Igvm,
}

/// The interrupt injection type that should be used for VMPL0 on SNP.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnpInjectionType {
    /// Normal injection.
    Normal,
    /// Restricted injection.
    Restricted,
}

/// The guest boot ABI encoded by an SNP Linux-direct IGVM.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnpLinuxDirectBootLayout {
    /// Shared KVM/MSHV layout with a sparse-RAM acceptance bootshim.
    #[default]
    Standard,
    /// MSHV-specific ACI Hyper-V layout with guest-managed RAM acceptance.
    AciHyperv,
}

/// Secure AVIC type.
#[derive(Serialize, Default, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SecureAvicType {
    /// Offload AVIC to the hardware.
    Enabled,
    /// The paravisor emulates APIC.
    #[default]
    Disabled,
}

/// The isolation type that should be used for the loader.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIsolationType {
    /// No isolation is present.
    None,
    /// Hypervisor based isolation (VBS) is present.
    Vbs {
        /// Boolean representing if the guest allows debugging
        enable_debug: bool,
    },
    /// AMD SEV-SNP.
    Snp {
        /// The optional shared GPA boundary to configure for the guest. A
        /// `None` value represents a guest that no shared GPA boundary is to be
        /// configured.
        shared_gpa_boundary_bits: Option<u8>,
        /// The SEV-SNP policy for the guest.
        policy: u64,
        /// Boolean representing if the guest allows debugging
        enable_debug: bool,
        /// The interrupt injection type to use for the highest vmpl.
        injection_type: SnpInjectionType,
        /// Secure AVIC
        #[serde(default)]
        secure_avic: SecureAvicType,
    },
    /// Intel TDX.
    Tdx {
        /// Boolean representing if the guest allows debugging
        enable_debug: bool,
        /// Boolean representing if the guest is disallowed from handling
        /// virtualization exceptions
        sept_ve_disable: bool,
    },
}

/// Configuration on what to load.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Image {
    /// Load nothing.
    None,
    /// Load UEFI.
    Uefi { config_type: UefiConfigType },
    /// Load the OpenHCL paravisor.
    Openhcl {
        /// The paravisor kernel command line.
        #[serde(default)]
        command_line: String,
        /// If false, the host may provide additional kernel command line
        /// parameters at runtime.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        static_command_line: bool,
        /// The base page number for paravisor memory. None means relocation is used.
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_page_base: Option<u64>,
        /// The number of pages for paravisor memory.
        memory_page_count: u64,
        /// Include the UEFI firmware for loading into the guest.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        uefi: bool,
        /// Include the Linux kernel for loading into the guest.
        #[serde(skip_serializing_if = "Option::is_none")]
        linux: Option<LinuxImage>,
        /// Optional measured product policy. When `Some`, the IGVM
        /// build emits the policy into the measured VTL2 config region.
        /// The manifest schema is the wire schema; see
        /// [`product_policy`]. We don't gate this property behind a feature
        /// to avoid having multiple igvmfilegen tools with and without the feature.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        product_policy: Option<ProductPolicy>,
    },
    /// Load the Linux kernel.
    /// TODO: Currently, this only works with underhill.
    Linux(LinuxImage),
    /// Load Linux directly into a self-contained SNP guest.
    SnpLinuxDirect {
        /// The Linux image to load.
        linux: LinuxImage,
        /// Processor topology shared with OpenVMM.
        processor_topology: X86ProcessorTopologyPlan,
        /// Address-space layout shared with OpenVMM.
        vm_layout: VmLayoutPlan,
        /// Guest boot ABI encoded in the IGVM.
        #[serde(default)]
        boot_layout: SnpLinuxDirectBootLayout,
        /// Explicit SNP encryption-bit position. When omitted, query host CPUID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        c_bit_position: Option<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct LinuxImage {
    /// Load with an initrd.
    pub use_initrd: bool,
    /// The command line to boot the kernel with.
    pub command_line: CString,
}

impl Image {
    /// Get the required resources for this image config.
    pub fn required_resources(&self) -> Vec<ResourceType> {
        match *self {
            Image::None => vec![],
            Image::Uefi { .. } => vec![ResourceType::Uefi],
            Image::Openhcl {
                uefi, ref linux, ..
            } => [
                ResourceType::UnderhillKernel,
                ResourceType::OpenhclBoot,
                ResourceType::UnderhillInitrd,
            ]
            .into_iter()
            .chain(if uefi { Some(ResourceType::Uefi) } else { None })
            .chain(linux.iter().flat_map(|linux| linux.required_resources()))
            .collect(),
            Image::Linux(ref linux) => linux.required_resources(),
            Image::SnpLinuxDirect {
                ref linux,
                boot_layout,
                ..
            } => linux
                .required_resources()
                .into_iter()
                .chain(
                    (boot_layout == SnpLinuxDirectBootLayout::Standard)
                        .then_some(ResourceType::SnpBootshim),
                )
                .collect(),
        }
    }

    /// Validate constraints intrinsic to this image configuration.
    pub fn validate(&self) -> Result<(), ImageValidationError> {
        if let Image::SnpLinuxDirect {
            processor_topology,
            ref vm_layout,
            c_bit_position,
            ..
        } = *self
        {
            if processor_topology.proc_count == 0 {
                return Err(ImageValidationError::ZeroProcessorCount);
            }
            let memory_byte_count = vm_layout
                .node_mem_sizes
                .iter()
                .try_fold(0u64, |total, size| total.checked_add(*size))
                .ok_or(ImageValidationError::MemoryByteCountOverflow)?;
            if memory_byte_count == 0 {
                return Err(ImageValidationError::ZeroMemoryPageCount);
            }
            if u32::try_from(memory_byte_count).is_err() {
                return Err(ImageValidationError::MemoryByteCountTooLarge {
                    memory_page_count: memory_byte_count / IGVM_PAGE_SIZE_BYTES,
                });
            }

            if let Some(c_bit_position) = c_bit_position
                && !X64_PAGE_TABLE_ADDRESS_BIT_RANGE.contains(&c_bit_position)
            {
                return Err(ImageValidationError::InvalidCBitPosition { c_bit_position });
            }
        }

        Ok(())
    }
}

/// Error returned when an image configuration contains invalid intrinsic fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageValidationError {
    /// The image requests no virtual processors.
    ZeroProcessorCount,
    /// The image requests no guest memory.
    ZeroMemoryPageCount,
    /// The requested memory byte count cannot be represented by an IGVM
    /// required-memory directive.
    MemoryByteCountTooLarge {
        /// The invalid number of 4-KiB pages.
        memory_page_count: u64,
    },
    /// The requested NUMA memory sizes overflow `u64`.
    MemoryByteCountOverflow,
    /// The SNP C-bit is outside the address bits available in x64 page tables.
    InvalidCBitPosition {
        /// The invalid C-bit position.
        c_bit_position: u8,
    },
}

impl std::fmt::Display for ImageValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ZeroProcessorCount => write!(f, "processor_count must be nonzero"),
            Self::ZeroMemoryPageCount => write!(f, "memory_page_count must be nonzero"),
            Self::MemoryByteCountTooLarge { memory_page_count } => write!(
                f,
                "memory_page_count {memory_page_count} has a byte count that does not fit in u32"
            ),
            Self::MemoryByteCountOverflow => write!(f, "memory byte count overflows u64"),
            Self::InvalidCBitPosition { c_bit_position } => write!(
                f,
                "c_bit_position {c_bit_position} is outside the supported range 32..=51"
            ),
        }
    }
}

impl std::error::Error for ImageValidationError {}

impl LinuxImage {
    fn required_resources(&self) -> Vec<ResourceType> {
        [ResourceType::LinuxKernel]
            .into_iter()
            .chain(if self.use_initrd {
                Some(ResourceType::LinuxInitrd)
            } else {
                None
            })
            .collect()
    }
}

/// The config used to describe an initial guest context to be generated by the
/// tool.
#[derive(Serialize, Deserialize, Debug)]
pub struct GuestConfig {
    /// The SVN of this guest.
    pub guest_svn: u32,
    /// The maximum VTL to be enabled for the guest.
    pub max_vtl: u8,
    /// The isolation type to be used for the guest.
    pub isolation_type: ConfigIsolationType,
    /// The image to load into the guest.
    pub image: Image,
}

impl GuestConfig {
    /// Validate image fields and isolation-dependent image requirements.
    pub fn validate(&self) -> Result<(), GuestConfigValidationError> {
        self.image
            .validate()
            .map_err(GuestConfigValidationError::Image)?;
        if matches!(
            &self.image,
            Image::SnpLinuxDirect {
                boot_layout: SnpLinuxDirectBootLayout::AciHyperv,
                ..
            }
        ) {
            if self.max_vtl != 0 {
                return Err(GuestConfigValidationError::AciRequiresVtl0);
            }
            match &self.isolation_type {
                ConfigIsolationType::Snp {
                    shared_gpa_boundary_bits: None,
                    injection_type: SnpInjectionType::Restricted,
                    ..
                } => {}
                ConfigIsolationType::Snp {
                    shared_gpa_boundary_bits: Some(_),
                    ..
                } => return Err(GuestConfigValidationError::AciSharedGpaBoundary),
                ConfigIsolationType::Snp { .. } => {
                    return Err(GuestConfigValidationError::AciRestrictedInjection);
                }
                _ => return Err(GuestConfigValidationError::AciRequiresSnp),
            }
        }
        Ok(())
    }
}

/// Error returned when guest and image configuration fields are inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestConfigValidationError {
    /// The image configuration is invalid.
    Image(ImageValidationError),
    /// The ACI layout is SNP-specific.
    AciRequiresSnp,
    /// The ACI layout is a VTL0 guest image.
    AciRequiresVtl0,
    /// The ACI VMSA must encode restricted injection.
    AciRestrictedInjection,
    /// The ACI layout does not use a shared GPA boundary.
    AciSharedGpaBoundary,
}

impl std::fmt::Display for GuestConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image(err) => err.fmt(f),
            Self::AciRequiresSnp => write!(f, "ACI Hyper-V boot layout requires SNP isolation"),
            Self::AciRequiresVtl0 => write!(f, "ACI Hyper-V boot layout requires max_vtl 0"),
            Self::AciRestrictedInjection => {
                write!(f, "ACI Hyper-V boot layout requires restricted injection")
            }
            Self::AciSharedGpaBoundary => {
                write!(
                    f,
                    "ACI Hyper-V boot layout does not support a shared GPA boundary"
                )
            }
        }
    }
}

impl std::error::Error for GuestConfigValidationError {}

/// The architecture of the igvm file.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GuestArch {
    /// x64
    X64,
    /// AArch64 aka ARM64
    Aarch64,
}

/// The config used to describe a multi-architecture IGVM file containing
/// multiple guests.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// The architecture of the igvm file.
    pub guest_arch: GuestArch,
    /// The array of guest configs to be used to generate a single IGVM file.
    pub guest_configs: Vec<GuestConfig>,
}

impl Config {
    /// Get a vec representing the required resources for this config.
    pub fn required_resources(&self) -> Vec<ResourceType> {
        let mut resources = vec![];
        for guest_config in &self.guest_configs {
            resources.extend(guest_config.image.required_resources());
        }
        resources
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Uefi,
    UnderhillKernel,
    OpenhclBoot,
    UnderhillInitrd,
    UnderhillSidecar,
    LinuxKernel,
    LinuxInitrd,
    SnpBootshim,
}

/// Resources used by igvmfilegen to generate IGVM files. These are generated by
/// build tooling and not checked into the repo.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Resources {
    /// The set of resources to use to generate IGVM files. These paths must be
    /// absolute.
    #[serde(deserialize_with = "parse::resources")]
    resources: HashMap<ResourceType, PathBuf>,
}

mod parse {
    use super::*;
    use serde::Deserialize;
    use serde::Deserializer;
    use std::collections::HashMap;

    pub fn resources<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<HashMap<ResourceType, PathBuf>, D::Error> {
        let resources: HashMap<ResourceType, PathBuf> = Deserialize::deserialize(d)?;

        for (resource, path) in &resources {
            if !path.is_absolute() {
                return Err(serde::de::Error::custom(AbsolutePathError(
                    *resource,
                    path.clone(),
                )));
            }
        }

        Ok(resources)
    }
}

/// Error returned when required resources are missing.
#[derive(Debug)]
pub struct MissingResourcesError(pub Vec<ResourceType>);

impl std::fmt::Display for MissingResourcesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing resources: {:?}", self.0)
    }
}

impl std::error::Error for MissingResourcesError {}

/// Error returned when a resource is not an absolute path.
#[derive(Debug)]
pub struct AbsolutePathError(ResourceType, PathBuf);

impl std::fmt::Display for AbsolutePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "resource {:?} path is not absolute: {:?}",
            self.0, self.1
        )
    }
}

impl std::error::Error for AbsolutePathError {}

impl Resources {
    /// Create a new set of resources. Returns an error if any of the paths are
    /// not absolute.
    pub fn new(resources: HashMap<ResourceType, PathBuf>) -> Result<Self, AbsolutePathError> {
        for (resource, path) in &resources {
            if !path.is_absolute() {
                return Err(AbsolutePathError(*resource, path.clone()));
            }
        }

        Ok(Resources { resources })
    }

    /// Get the resources for this set.
    pub fn resources(&self) -> &HashMap<ResourceType, PathBuf> {
        &self.resources
    }

    /// Get the resource path for a given resource type.
    pub fn get(&self, resource: ResourceType) -> Option<&PathBuf> {
        self.resources.get(&resource)
    }

    /// Check that the required resources are present. On error, returns which
    /// resources are missing.
    pub fn check_required(&self, required: &[ResourceType]) -> Result<(), MissingResourcesError> {
        let mut missing = vec![];
        for resource in required {
            if !self.resources.contains_key(resource) {
                missing.push(*resource);
            }
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(MissingResourcesError(missing))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn snp_linux_direct_image(
        use_initrd: bool,
        processor_count: u32,
        memory_page_count: u64,
        c_bit_position: Option<u8>,
        boot_layout: SnpLinuxDirectBootLayout,
    ) -> Image {
        Image::SnpLinuxDirect {
            linux: LinuxImage {
                use_initrd,
                command_line: CString::new("console=ttyS0").unwrap(),
            },
            processor_topology: X86ProcessorTopologyPlan {
                proc_count: processor_count,
                vps_per_socket: Some(1),
                enable_smt: Some(false),
                apic_id_offset: 0,
                x2apic: openvmm_vm_layout::X2ApicModePlan::Supported,
            },
            vm_layout: VmLayoutPlan {
                node_mem_sizes: vec![memory_page_count * IGVM_PAGE_SIZE_BYTES],
                layout: openvmm_vm_layout::LayoutPlan {
                    chipset_low_mmio_size: 128 * 1024 * 1024,
                    chipset_high_mmio_size: 0,
                    vtl2_chipset_mmio_size: 0,
                },
                pcie_root_complexes: Vec::new(),
                virtio_mmio_count: 0,
                pcie_ecam_below_4gb: true,
                vtl2_layout: None,
                ram_start_address: 0,
                vtl2_framebuffer_size: 0,
                physical_address_size: 48,
            },
            boot_layout,
            c_bit_position,
        }
    }

    #[test]
    fn parse_snp_linux_direct_manifest() {
        let config: Config =
            serde_json::from_str(include_str!("../../manifests/snp-linux-direct.json")).unwrap();

        assert!(matches!(config.guest_arch, GuestArch::X64));
        let [guest] = config.guest_configs.as_slice() else {
            panic!("expected one guest config");
        };
        assert_eq!(guest.guest_svn, 1);
        assert_eq!(guest.max_vtl, 0);
        match &guest.isolation_type {
            ConfigIsolationType::Snp {
                shared_gpa_boundary_bits,
                policy,
                enable_debug,
                injection_type,
                secure_avic,
            } => {
                assert_eq!(*shared_gpa_boundary_bits, None);
                assert_eq!(*policy, 196608);
                assert!(*enable_debug);
                assert!(matches!(injection_type, SnpInjectionType::Normal));
                assert!(matches!(secure_avic, SecureAvicType::Disabled));
            }

            isolation_type => panic!("unexpected isolation type: {isolation_type:?}"),
        }
        match &guest.image {
            Image::SnpLinuxDirect {
                linux,
                processor_topology,
                vm_layout,
                boot_layout,
                c_bit_position,
            } => {
                assert!(linux.use_initrd);
                assert_eq!(
                    linux.command_line.as_bytes(),
                    b"console=ttyS0 earlyprintk=serial earlycon panic=-1"
                );
                assert_eq!(processor_topology.proc_count, 1);
                assert_eq!(vm_layout.node_mem_sizes, [40960 * IGVM_PAGE_SIZE_BYTES]);
                assert_eq!(*boot_layout, SnpLinuxDirectBootLayout::Standard);
                assert_eq!(*c_bit_position, Some(51));
                guest.image.validate().unwrap();
            }
            image => panic!("unexpected image: {image:?}"),
        }
    }

    #[test]
    fn parse_multi_vp_snp_linux_direct_manifest() {
        let config: Config = serde_json::from_str(include_str!(
            "../../manifests/snp-linux-direct-multi-vp.json"
        ))
        .unwrap();
        let [guest] = config.guest_configs.as_slice() else {
            panic!("expected one guest config");
        };
        let Image::SnpLinuxDirect {
            processor_topology, ..
        } = &guest.image
        else {
            panic!("expected SNP Linux-direct image");
        };
        assert_eq!(processor_topology.proc_count, 2);
        guest.image.validate().unwrap();
    }

    #[test]
    fn parse_restricted_snp_linux_direct_manifest() {
        let normal: serde_json::Value =
            serde_json::from_str(include_str!("../../manifests/snp-linux-direct.json")).unwrap();
        let mut restricted: serde_json::Value = serde_json::from_str(include_str!(
            "../../manifests/snp-linux-direct-restricted.json"
        ))
        .unwrap();
        let config: Config = serde_json::from_value(restricted.clone()).unwrap();

        let injection_type = restricted
            .pointer_mut("/guest_configs/0/isolation_type/snp/injection_type")
            .unwrap();
        assert_eq!(injection_type.as_str(), Some("restricted"));
        *injection_type = serde_json::Value::String("normal".into());
        assert_eq!(restricted, normal);

        let [guest] = config.guest_configs.as_slice() else {
            panic!("expected one guest config");
        };
        assert!(matches!(
            &guest.isolation_type,
            ConfigIsolationType::Snp {
                injection_type: SnpInjectionType::Restricted,
                ..
            }
        ));
        let Image::SnpLinuxDirect {
            processor_topology,
            boot_layout,
            ..
        } = &guest.image
        else {
            panic!("expected SNP Linux-direct image");
        };
        assert_eq!(processor_topology.proc_count, 1);
        assert_eq!(*boot_layout, SnpLinuxDirectBootLayout::Standard);
        guest.image.validate().unwrap();
    }

    #[test]
    fn parse_aci_snp_linux_direct_manifest() {
        let config: Config =
            serde_json::from_str(include_str!("../../manifests/snp-linux-direct-aci.json"))
                .unwrap();
        let [guest] = config.guest_configs.as_slice() else {
            panic!("expected one guest config");
        };
        assert!(matches!(
            &guest.isolation_type,
            ConfigIsolationType::Snp {
                injection_type: SnpInjectionType::Restricted,
                ..
            }
        ));
        let Image::SnpLinuxDirect {
            processor_topology,
            boot_layout,
            ..
        } = &guest.image
        else {
            panic!("expected SNP Linux-direct image");
        };
        assert_eq!(processor_topology.proc_count, 1);
        assert_eq!(*boot_layout, SnpLinuxDirectBootLayout::AciHyperv);
        guest.image.validate().unwrap();
        guest.validate().unwrap();
    }

    #[test]
    fn aci_snp_linux_direct_requires_restricted_injection() {
        let mut config: Config =
            serde_json::from_str(include_str!("../../manifests/snp-linux-direct-aci.json"))
                .unwrap();
        let [guest] = config.guest_configs.as_mut_slice() else {
            panic!("expected one guest config");
        };
        let ConfigIsolationType::Snp { injection_type, .. } = &mut guest.isolation_type else {
            panic!("expected SNP isolation");
        };
        *injection_type = SnpInjectionType::Normal;

        assert_eq!(
            guest.validate(),
            Err(GuestConfigValidationError::AciRestrictedInjection)
        );
    }

    #[test]
    fn snp_linux_direct_required_resources_with_initrd() {
        let image =
            snp_linux_direct_image(true, 1, 40960, Some(51), SnpLinuxDirectBootLayout::Standard);

        assert_eq!(
            image.required_resources(),
            vec![
                ResourceType::LinuxKernel,
                ResourceType::LinuxInitrd,
                ResourceType::SnpBootshim
            ]
        );
    }

    #[test]
    fn snp_linux_direct_required_resources_without_initrd() {
        let image = snp_linux_direct_image(
            false,
            1,
            40960,
            Some(51),
            SnpLinuxDirectBootLayout::Standard,
        );

        assert_eq!(
            image.required_resources(),
            vec![ResourceType::LinuxKernel, ResourceType::SnpBootshim]
        );
    }

    #[test]
    fn aci_snp_linux_direct_does_not_require_bootshim() {
        let image = snp_linux_direct_image(
            true,
            2,
            40960,
            Some(51),
            SnpLinuxDirectBootLayout::AciHyperv,
        );

        assert_eq!(
            image.required_resources(),
            vec![ResourceType::LinuxKernel, ResourceType::LinuxInitrd]
        );
    }

    #[test]
    fn snp_linux_direct_rejects_zero_memory() {
        let image =
            snp_linux_direct_image(false, 1, 0, Some(51), SnpLinuxDirectBootLayout::Standard);

        assert_eq!(
            image.validate(),
            Err(ImageValidationError::ZeroMemoryPageCount)
        );
    }

    #[test]
    fn snp_linux_direct_rejects_oversized_memory() {
        let memory_page_count = u64::from(u32::MAX) / IGVM_PAGE_SIZE_BYTES + 1;
        let image = snp_linux_direct_image(
            false,
            1,
            memory_page_count,
            Some(51),
            SnpLinuxDirectBootLayout::Standard,
        );

        assert_eq!(
            image.validate(),
            Err(ImageValidationError::MemoryByteCountTooLarge { memory_page_count })
        );
    }

    #[test]
    fn snp_linux_direct_rejects_invalid_c_bit_positions() {
        for c_bit_position in [31, 52] {
            let image = snp_linux_direct_image(
                false,
                1,
                40960,
                Some(c_bit_position),
                SnpLinuxDirectBootLayout::Standard,
            );

            assert_eq!(
                image.validate(),
                Err(ImageValidationError::InvalidCBitPosition { c_bit_position })
            );
        }
    }

    #[test]
    fn snp_linux_direct_rejects_zero_processors() {
        let image = snp_linux_direct_image(
            false,
            0,
            40960,
            Some(51),
            SnpLinuxDirectBootLayout::Standard,
        );

        assert_eq!(
            image.validate(),
            Err(ImageValidationError::ZeroProcessorCount)
        );
    }

    #[test]
    fn non_absolute_path_new() {
        let mut resources = HashMap::new();
        resources.insert(ResourceType::Uefi, PathBuf::from("./uefi"));
        let result = Resources::new(resources);
        assert!(result.is_err());
    }

    #[test]
    fn parse_non_absolute_path() {
        let resources = r#"{"uefi":"./uefi"}"#;
        let result: Result<Resources, _> = serde_json::from_str(resources);
        assert!(result.is_err());
    }

    #[test]
    fn missing_resources() {
        let resources = Resources {
            resources: HashMap::new(),
        };
        let required = vec![ResourceType::Uefi];
        let result = resources.check_required(&required);
        assert!(result.is_err());
    }

    #[test]
    fn openhcl_image_without_product_policy_round_trips() {
        // Older manifests omit the field; serialization must too.
        let json = r#"{"openhcl":{"command_line":"","memory_page_count":10,"uefi":true}}"#;
        let parsed: Image = serde_json::from_str(json).unwrap();
        match &parsed {
            Image::Openhcl { product_policy, .. } => assert!(product_policy.is_none()),
            other => panic!("unexpected parse: {other:?}"),
        }
        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert!(
            !reserialized.contains("product_policy"),
            "policy field should be omitted when None: {reserialized}"
        );
    }

    #[test]
    fn openhcl_image_with_sivm_product_policy_deserializes() {
        let json = r#"{
            "openhcl": {
                "command_line": "",
                "memory_page_count": 10,
                "uefi": true,
                "product_policy": {
                    "sivm": {
                        "require_ephemeral_vmgs": true,
                        "require_secure_boot": true,
                        "require_secure_boot_vars": true,
                        "require_bcd_integrity": true,
                        "custom_uefi_json": "ZGVhZGJlZWY="
                    }
                }
            }
        }"#;
        let parsed: Image = serde_json::from_str(json).unwrap();
        match parsed {
            Image::Openhcl {
                product_policy: Some(policy),
                ..
            } => match policy {
                ProductPolicy::Sivm(p) => {
                    assert!(p.require_ephemeral_vmgs);
                    assert!(p.require_secure_boot);
                    assert!(p.require_secure_boot_vars);
                    assert!(p.require_bcd_integrity);
                    assert_eq!(p.custom_uefi_json, b"deadbeef");
                }
                ProductPolicy::Cwcow(p) => panic!("unexpected Cwcow policy: {p:?}"),
            },
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn openhcl_image_with_null_product_policy_is_absent() {
        let json = r#"{
            "openhcl": {
                "command_line": "",
                "memory_page_count": 10,
                "uefi": true,
                "product_policy": null
            }
        }"#;
        let parsed: Image = serde_json::from_str(json).unwrap();
        match parsed {
            Image::Openhcl { product_policy, .. } => assert!(product_policy.is_none()),
            other => panic!("unexpected parse: {other:?}"),
        }
    }
}
