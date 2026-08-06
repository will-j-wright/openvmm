// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generation strategy for a self-contained SNP Linux-direct IGVM.

use crate::identity_mapping::Measurement;
use crate::identity_mapping::SnpMeasurement;
use crate::signed_measurement::snp::SnpImageIdentity;
use crate::signed_measurement::snp::generate_snp_measurement;
use anyhow::Context;
use anyhow::bail;
use anyhow::ensure;
use igvm::IgvmDirectiveHeader;
use igvm::IgvmFile;
use igvm::IgvmInitializationHeader;
use igvm::IgvmPlatformHeader;
use igvm::IgvmRevision;
use igvm::snp_defs::SevFeatures;
use igvm::snp_defs::SevSelector;
use igvm::snp_defs::SevVmsa;
use igvm_defs::IGVM_VHS_PARAMETER;
use igvm_defs::IGVM_VHS_PARAMETER_INSERT;
use igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM;
use igvm_defs::IgvmPageDataFlags;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
use igvm_defs::SnpPolicy;
use igvmfilegen_config::LinuxImage;
use igvmfilegen_config::ResourceType;
use igvmfilegen_config::Resources;
use igvmfilegen_config::SnpInjectionType;
use igvmfilegen_config::SnpLinuxDirectBootLayout;
use loader::importer::BootPageAcceptance;
use loader::importer::IgvmParameterType;
use loader::importer::ImageLoad;
use loader::importer::IsolationConfig;
use loader::importer::IsolationType;
use loader::importer::ParameterAreaIndex;
use loader::importer::SegmentRegister;
use loader::importer::StartupMemoryType;
use loader::importer::TableRegister;
use loader::importer::X86Register;
use loader::linux::InitrdAddressType;
use loader::linux::InitrdConfig;
use loader_defs::linux::SNP_ACI_IGVM_CONFIG_MAGIC;
use loader_defs::linux::SNP_ACI_IGVM_CONFIG_VERSION;
use loader_defs::linux::SNP_ACI_IGVM_MAX_VPS;
use loader_defs::linux::SNP_BOOT_SHIM_MAX_RANGES;
use loader_defs::linux::SNP_BOOT_SHIM_PARAMS_MAGIC;
use loader_defs::linux::SNP_BOOT_SHIM_PARAMS_VERSION;
use loader_defs::linux::SnpAciIgvmConfig;
use loader_defs::linux::SnpBootShimParams;
use loader_defs::linux::SnpBootShimRange;
use memory_range::MemoryRange;
use openvmm_vm_layout::VmLayoutPlan;
use openvmm_vm_layout::X86ProcessorTopologyPlan;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Seek;
use std::mem::discriminant;
use thiserror::Error;
use vm_topology::memory::MemoryRangeWithNode;
#[cfg(any(target_arch = "x86_64", test))] // xtask-fmt allow-target-arch cpu-intrinsic
use x86defs::cpuid::CpuidFunction;
#[cfg(any(target_arch = "x86_64", test))] // xtask-fmt allow-target-arch cpu-intrinsic
use x86defs::cpuid::ExtendedSevFeaturesEax;
#[cfg(any(target_arch = "x86_64", test))] // xtask-fmt allow-target-arch cpu-intrinsic
use x86defs::cpuid::ExtendedSevFeaturesEbx;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

const COMPATIBILITY_MASK: u32 = 1;
const PAGE_SIZE: u64 = igvm_defs::PAGE_SIZE_4K;
/// KVM hardcodes the initial VMSA at this GPA and measures it during launch
/// finish, after all userspace-provided launch-update pages.
const KVM_VMSA_GPA: u64 = 0xffff_ffff_f000;
const PM_BASE: u16 = 0x400;
const ACPI_IRQ: u32 = 9;
const COM1_BASE: u16 = 0x3f8;
const COM1_IRQ: u32 = 4;

pub struct BuildParams<'a> {
    pub linux: &'a LinuxImage,
    pub processor_topology: &'a X86ProcessorTopologyPlan,
    pub vm_layout: &'a VmLayoutPlan,
    pub boot_layout: SnpLinuxDirectBootLayout,
    pub c_bit_position: Option<u8>,
    pub guest_svn: u32,
    pub policy: SnpPolicy,
    pub injection_type: &'a SnpInjectionType,
    pub resources: &'a Resources,
}

pub struct BuildOutput {
    pub guest: IgvmFile,
    pub map: String,
    pub measurement: Measurement,
}

#[derive(Debug, Error)]
enum ConfigError {
    #[error("SNP Linux-direct requires exactly one NUMA node, found {0}")]
    Numa(usize),
    #[error("SNP Linux-direct requires RAM to start at GPA 0")]
    RamStart,
    #[error("SNP Linux-direct requires one contiguous RAM range, found {0}")]
    RamRanges(usize),
    #[error("SNP Linux-direct RAM size {0:#x} does not fit in an IGVM required-memory directive")]
    RamTooLarge(u64),
    #[error("SNP Linux-direct does not support VTL2 memory")]
    Vtl2,
    #[error("SNP Linux-direct does not support VTL2 chipset MMIO")]
    Vtl2ChipsetMmio,
    #[error("SNP Linux-direct does not support a framebuffer")]
    Framebuffer,
    #[error("SNP Linux-direct does not support virtio-mmio devices")]
    VirtioMmio,
    #[error("SNP Linux-direct requires PCIe ECAM below 4 GiB")]
    HighPcieEcam,
    #[error("SNP Linux-direct does not support CXL on root complex '{0}'")]
    Cxl(String),
    #[error("SNP Linux-direct does not support an IOMMU on root complex '{0}'")]
    Iommu(String),
    #[error("host CPUID does not report SEV-SNP C-bit information")]
    MissingHostCBit,
}

#[derive(Debug, Clone)]
struct ImportedPage {
    acceptance: BootPageAcceptance,
    data: Vec<u8>,
    tag: &'static str,
}

#[derive(Debug)]
struct IgvmParameterArea {
    page_base: u64,
    page_count: u32,
    initial_data: Vec<u8>,
    parameters: Vec<(u32, IgvmParameterType)>,
    tag: String,
}

#[derive(Debug, Clone, Copy)]
struct VmsaDirectiveConfig {
    gpa: u64,
    context_count: u32,
}

#[derive(Debug)]
enum ExpectedBootLayout {
    Standard {
        shim_entry: u64,
        params_gpa: u64,
        params: Box<SnpBootShimParams>,
    },
    AciHyperv {
        linux_entry: u64,
        linux_zero_page: u64,
        vmsa_gpa: u64,
        parameter_gpa: u64,
        expected_apic_ids: Vec<u32>,
    },
}

#[derive(Debug)]
struct TestIgvmImporter {
    pages: BTreeMap<u64, ImportedPage>,
    parameter_areas: Vec<IgvmParameterArea>,
    reserved_pages: BTreeSet<u64>,
    registers: Vec<X86Register>,
    ram_page_count: u64,
    c_bit_mask: u64,
    use_loader_vmsa_gpa: bool,
    vp_context_page: Option<u64>,
}

impl TestIgvmImporter {
    fn new(ram_page_count: u64, c_bit_position: u8, boot_layout: SnpLinuxDirectBootLayout) -> Self {
        Self {
            pages: BTreeMap::new(),
            parameter_areas: Vec::new(),
            reserved_pages: BTreeSet::new(),
            registers: Vec::new(),
            ram_page_count,
            c_bit_mask: 1u64 << c_bit_position,
            use_loader_vmsa_gpa: boot_layout == SnpLinuxDirectBootLayout::AciHyperv,
            vp_context_page: None,
        }
    }

    fn finish(
        self,
        injection_type: &SnpInjectionType,
        bootshim_ranges: &[SnpBootShimRange],
        vmsa_config: VmsaDirectiveConfig,
    ) -> anyhow::Result<(Vec<IgvmDirectiveHeader>, SevVmsa, String)> {
        let vmsa = build_vmsa(&self.registers, self.c_bit_mask, injection_type)?;
        let (mut directives, map) = build_sparse_ram_directives(
            &self.pages,
            &self.parameter_areas,
            &vmsa,
            vmsa_config,
            self.ram_page_count,
            bootshim_ranges,
        )?;
        let ram_size = self
            .ram_page_count
            .checked_mul(PAGE_SIZE)
            .context("RAM size overflow")?;
        directives.insert(
            0,
            IgvmDirectiveHeader::RequiredMemory {
                gpa: 0,
                compatibility_mask: COMPATIBILITY_MASK,
                number_of_bytes: ram_size
                    .try_into()
                    .context("RAM size does not fit in an IGVM required-memory directive")?,
                vtl2_protectable: false,
            },
        );
        Ok((directives, vmsa, map))
    }

    fn next_available_gpa(&self) -> anyhow::Result<u64> {
        let last_page = self
            .pages
            .last_key_value()
            .map(|(&page, _)| page)
            .into_iter()
            .chain(self.reserved_pages.last().copied())
            .max();
        last_page.map_or(Ok(0), |page| {
            page.checked_add(1)
                .and_then(|page| page.checked_mul(PAGE_SIZE))
                .context("next imported address overflow")
        })
    }

    fn register_value(
        &self,
        name: &'static str,
        value: impl Fn(X86Register) -> Option<u64>,
    ) -> anyhow::Result<u64> {
        self.registers
            .iter()
            .copied()
            .find_map(value)
            .with_context(|| format!("Linux loader did not provide {name}"))
    }

    fn replace_register(&mut self, replacement: X86Register) -> anyhow::Result<()> {
        let replacement_kind = discriminant(&replacement);
        let index = self
            .registers
            .iter()
            .position(|register| discriminant(register) == replacement_kind)
            .context("initial register to replace is missing")?;
        self.registers[index] = replacement;
        Ok(())
    }

    fn unimported_ranges(
        &self,
        additional_imported_pages: impl IntoIterator<Item = u64>,
    ) -> anyhow::Result<Vec<SnpBootShimRange>> {
        let imported_pages = self
            .pages
            .keys()
            .copied()
            .chain(additional_imported_pages)
            .collect::<BTreeSet<_>>();
        ensure!(
            imported_pages
                .last()
                .is_none_or(|page| *page < self.ram_page_count),
            "an imported page lies outside RAM"
        );

        let mut ranges = Vec::new();
        let mut cursor = 0;
        for page in imported_pages {
            if cursor < page {
                ranges.push(SnpBootShimRange {
                    start_gpn: cursor,
                    page_count: page - cursor,
                });
            }
            cursor = page + 1;
        }
        if cursor < self.ram_page_count {
            ranges.push(SnpBootShimRange {
                start_gpn: cursor,
                page_count: self.ram_page_count - cursor,
            });
        }
        Ok(ranges)
    }

    fn complete_initial_ranges(&mut self, ranges: &[MemoryRange]) -> anyhow::Result<()> {
        for range in ranges {
            ensure!(
                range.start().is_multiple_of(PAGE_SIZE) && range.end().is_multiple_of(PAGE_SIZE),
                "ACI initial import range is not page aligned"
            );
            for page in range.start() / PAGE_SIZE..range.end() / PAGE_SIZE {
                if self.pages.contains_key(&page) || self.reserved_pages.contains(&page) {
                    continue;
                }
                self.pages.insert(
                    page,
                    ImportedPage {
                        acceptance: BootPageAcceptance::Exclusive,
                        data: Vec::new(),
                        tag: "aci-initial-image",
                    },
                );
            }
        }
        Ok(())
    }

    fn vmsa_gpa(&self) -> anyhow::Result<u64> {
        if self.use_loader_vmsa_gpa {
            self.vp_context_page
                .and_then(|page| page.checked_mul(PAGE_SIZE))
                .context("ACI loader did not provide a valid VP context page")
        } else {
            Ok(KVM_VMSA_GPA)
        }
    }
}

impl ImageLoad<X86Register> for TestIgvmImporter {
    fn isolation_config(&self) -> IsolationConfig {
        IsolationConfig {
            paravisor_present: false,
            isolation_type: IsolationType::Snp,
            shared_gpa_boundary_bits: None,
        }
    }

    fn create_parameter_area(
        &mut self,
        page_base: u64,
        page_count: u32,
        debug_tag: &str,
    ) -> anyhow::Result<ParameterAreaIndex> {
        self.create_parameter_area_with_data(page_base, page_count, debug_tag, &[])
    }

    fn create_parameter_area_with_data(
        &mut self,
        page_base: u64,
        page_count: u32,
        debug_tag: &str,
        initial_data: &[u8],
    ) -> anyhow::Result<ParameterAreaIndex> {
        ensure!(page_count != 0, "cannot create an empty parameter area");
        let page_end = page_base
            .checked_add(u64::from(page_count))
            .context("parameter area range overflow")?;
        ensure!(
            page_end <= self.ram_page_count,
            "{debug_tag} lies outside the configured RAM layout"
        );
        let byte_count = u64::from(page_count) * PAGE_SIZE;
        ensure!(
            initial_data.is_empty() || initial_data.len() as u64 == byte_count,
            "{debug_tag} initial data must be empty or fill the parameter area"
        );
        for page in page_base..page_end {
            ensure!(
                !self.pages.contains_key(&page) && self.reserved_pages.insert(page),
                "{debug_tag} overlaps an existing import at GPA {:#x}",
                page * PAGE_SIZE
            );
        }
        let index = self
            .parameter_areas
            .len()
            .try_into()
            .context("too many IGVM parameter areas")?;
        self.parameter_areas.push(IgvmParameterArea {
            page_base,
            page_count,
            initial_data: initial_data.to_vec(),
            parameters: Vec::new(),
            tag: debug_tag.to_owned(),
        });
        Ok(ParameterAreaIndex(index))
    }

    fn import_parameter(
        &mut self,
        parameter_area: ParameterAreaIndex,
        byte_offset: u32,
        parameter_type: IgvmParameterType,
    ) -> anyhow::Result<()> {
        let area = self
            .parameter_areas
            .get_mut(parameter_area.0 as usize)
            .context("invalid IGVM parameter area index")?;
        area.parameters.push((byte_offset, parameter_type));
        Ok(())
    }

    fn import_pages(
        &mut self,
        page_base: u64,
        page_count: u64,
        debug_tag: &'static str,
        acceptance: BootPageAcceptance,
        data: &[u8],
    ) -> anyhow::Result<()> {
        ensure!(page_count != 0, "cannot import an empty page range");
        let byte_capacity = page_count
            .checked_mul(PAGE_SIZE)
            .context("imported page range size overflow")?;
        ensure!(
            data.len() as u64 <= byte_capacity,
            "data for {debug_tag} exceeds its imported page range"
        );
        let page_end = page_base
            .checked_add(page_count)
            .context("imported page range overflow")?;
        ensure!(
            page_end <= self.ram_page_count,
            "{debug_tag} lies outside the configured RAM layout"
        );

        for page_offset in 0..page_count {
            let data_start = (page_offset * PAGE_SIZE) as usize;
            let data_end = data
                .len()
                .min(data_start.saturating_add(PAGE_SIZE as usize));
            let page_data = if data_start < data.len() {
                data[data_start..data_end].to_vec()
            } else {
                Vec::new()
            };
            let page_number = page_base + page_offset;
            ensure!(
                !self.reserved_pages.contains(&page_number),
                "{debug_tag} overlaps a reserved page at GPA {:#x}",
                page_number * PAGE_SIZE
            );
            let previous = self.pages.insert(
                page_number,
                ImportedPage {
                    acceptance,
                    data: page_data,
                    tag: debug_tag,
                },
            );
            ensure!(
                previous.is_none(),
                "{debug_tag} overlaps an existing import at GPA {:#x}",
                page_number * PAGE_SIZE
            );
        }
        Ok(())
    }

    fn import_vp_register(&mut self, register: X86Register) -> anyhow::Result<()> {
        ensure!(
            !self
                .registers
                .iter()
                .any(|existing| discriminant(existing) == discriminant(&register)),
            "duplicate initial register {register:?}"
        );
        self.registers.push(register);
        Ok(())
    }

    fn verify_startup_memory_available(
        &mut self,
        page_base: u64,
        page_count: u64,
        _memory_type: StartupMemoryType,
    ) -> anyhow::Result<()> {
        let page_end = page_base
            .checked_add(page_count)
            .context("required memory range overflow")?;
        ensure!(
            page_end <= self.ram_page_count,
            "required memory lies outside the configured RAM layout"
        );
        Ok(())
    }

    fn set_vp_context_page(&mut self, page_base: u64) -> anyhow::Result<()> {
        ensure!(
            page_base < self.ram_page_count,
            "Linux-selected VP context page lies outside RAM"
        );
        if self.use_loader_vmsa_gpa {
            ensure!(
                self.vp_context_page.replace(page_base).is_none(),
                "Linux-selected VP context page was already configured"
            );
            ensure!(
                !self.pages.contains_key(&page_base) && self.reserved_pages.insert(page_base),
                "Linux-selected VP context page overlaps an existing import"
            );
        }
        Ok(())
    }

    fn relocation_region(
        &mut self,
        _gpa: u64,
        _size_bytes: u64,
        _relocation_alignment: u64,
        _minimum_relocation_gpa: u64,
        _maximum_relocation_gpa: u64,
        _apply_rip_offset: bool,
        _apply_gdtr_offset: bool,
        _vp_index: u16,
    ) -> anyhow::Result<()> {
        bail!("relocations are not supported by this fixed image")
    }

    fn page_table_relocation(
        &mut self,
        _page_table_gpa: u64,
        _size_pages: u64,
        _used_pages: u64,
        _vp_index: u16,
    ) -> anyhow::Result<()> {
        bail!("page-table relocations are not supported by this fixed image")
    }

    fn set_imported_regions_config_page(&mut self, _page_base: u64) {}
}

pub fn build(params: BuildParams<'_>) -> anyhow::Result<BuildOutput> {
    let BuildParams {
        linux,
        processor_topology,
        vm_layout,
        boot_layout,
        c_bit_position,
        guest_svn,
        policy,
        injection_type,
        resources,
    } = params;
    validate_plan(vm_layout)?;
    let c_bit_position = resolve_c_bit_position(c_bit_position)?;
    let resolved_layout = vm_layout.resolve().context("resolving VM layout")?;
    let pcie_host_bridges = vm_layout
        .pcie_host_bridges(&resolved_layout.pcie_root_complex_ranges)
        .context("building PCIe host bridges")?;
    let memory_layout = &resolved_layout.memory_layout;
    let [MemoryRangeWithNode { range: ram, .. }] = memory_layout.ram() else {
        return Err(ConfigError::RamRanges(memory_layout.ram().len()).into());
    };
    if ram.start() != 0 {
        return Err(ConfigError::RamStart.into());
    }
    let memory_size = ram.len();
    let memory_page_count = memory_size / PAGE_SIZE;
    u32::try_from(memory_size).map_err(|_| ConfigError::RamTooLarge(memory_size))?;
    let processor_topology = processor_topology
        .resolve()
        .context("building processor topology")?;
    let processor_count = processor_topology.vp_count();
    let acpi_builder = vmm_core::acpi_builder::AcpiTablesBuilder {
        processor_topology: &processor_topology,
        mem_layout: memory_layout,
        cache_topology: None,
        pcie_host_bridges: &pcie_host_bridges,
        slit_info: None,
        generic_initiators: &[],
        arch: vmm_core::acpi_builder::AcpiArchConfig::X86 {
            with_ioapic: true,
            with_pic: true,
            with_pit: true,
            with_psp: false,
            pm_base: PM_BASE,
            acpi_irq: ACPI_IRQ,
            iommu: None,
        },
    };

    let kernel_path = resources
        .get(ResourceType::LinuxKernel)
        .context("Linux kernel resource is missing")?;
    let mut kernel = fs_err::File::open(kernel_path)
        .with_context(|| format!("opening kernel {}", kernel_path.display()))?;
    let mut initrd = if linux.use_initrd {
        let initrd_path = resources
            .get(ResourceType::LinuxInitrd)
            .context("Linux initrd resource is missing")?;
        Some(
            fs_err::File::open(initrd_path)
                .with_context(|| format!("opening initrd {}", initrd_path.display()))?,
        )
    } else {
        None
    };
    let initrd_config = if let Some(initrd) = &mut initrd {
        let size = initrd
            .seek(std::io::SeekFrom::End(0))
            .context("measuring initrd")?;
        initrd.rewind().context("rewinding initrd")?;
        Some(InitrdConfig {
            initrd_address: InitrdAddressType::AfterKernel,
            initrd,
            size,
        })
    } else {
        None
    };

    let mut importer = TestIgvmImporter::new(memory_page_count, c_bit_position, boot_layout);
    let load_info = loader::linux::load_x86(
        &mut importer,
        &mut kernel,
        initrd_config,
        &linux.command_line,
        memory_layout,
        |gpa| {
            let tables = acpi_builder.build_acpi_tables(gpa, |dsdt| {
                dsdt.add_apic();
                dsdt.add_uart(b"\\_SB.UAR1", b"COM1", 1, COM1_BASE, COM1_IRQ);
                dsdt.add_rtc();
            });
            loader::linux::AcpiTables {
                rsdp: tables.rsdp,
                tables: tables.tables,
            }
        },
        None,
        Some(loader::linux::SnpBootConfig {
            c_bit: c_bit_position,
            aci_hyperv: (boot_layout == SnpLinuxDirectBootLayout::AciHyperv)
                .then_some(loader::linux::AciHypervSnpBootConfig::Igvm),
        }),
    )
    .context("loading direct-Linux image")?;

    let linux_entry = importer.register_value("Linux entry point", |register| match register {
        X86Register::Rip(value) => Some(value),
        _ => None,
    })?;
    let linux_zero_page =
        importer.register_value("Linux zero-page address", |register| match register {
            X86Register::Rsi(value) => Some(value),
            _ => None,
        })?;

    let (bootshim_ranges, vmsa_config, expected_boot_layout) = match boot_layout {
        SnpLinuxDirectBootLayout::Standard => {
            let kernel_runtime_end = load_info
                .kernel
                .gpa
                .checked_add(
                    load_info
                        .bzimage_setup_header
                        .as_ref()
                        .map_or(load_info.kernel.size, |header| u64::from(header.init_size)),
                )
                .context("Linux runtime image end overflow")?;
            let shim_base =
                align_up_to_page(importer.next_available_gpa()?.max(kernel_runtime_end))?;
            let bootshim_path = resources
                .get(ResourceType::SnpBootshim)
                .context("SNP bootshim resource is missing")?;
            let mut bootshim = fs_err::File::open(bootshim_path)
                .with_context(|| format!("opening SNP bootshim {}", bootshim_path.display()))?;
            let shim_load_info = loader::elf::load_static_elf(
                &mut importer,
                &mut bootshim,
                0,
                shim_base,
                false,
                BootPageAcceptance::Exclusive,
                "snp-bootshim",
            )
            .context("loading SNP bootshim")?;
            let params_gpa = align_up_to_page(shim_load_info.next_available_address)?;
            let params_page = params_gpa / PAGE_SIZE;
            ensure!(
                params_page < memory_page_count,
                "SNP bootshim parameter page lies outside configured RAM"
            );

            let bootshim_ranges = importer.unimported_ranges([params_page])?;
            let bootshim_params =
                build_bootshim_params(linux_entry, linux_zero_page, memory_size, &bootshim_ranges)?;
            importer
                .import_pages(
                    params_page,
                    1,
                    "snp-bootshim-params",
                    BootPageAcceptance::Exclusive,
                    bootshim_params.as_bytes(),
                )
                .context("importing SNP bootshim parameters")?;
            importer.replace_register(X86Register::Rip(shim_load_info.entrypoint))?;
            importer.replace_register(X86Register::Rsi(params_gpa))?;

            (
                bootshim_ranges,
                VmsaDirectiveConfig {
                    gpa: KVM_VMSA_GPA,
                    context_count: processor_count,
                },
                ExpectedBootLayout::Standard {
                    shim_entry: shim_load_info.entrypoint,
                    params_gpa,
                    params: Box::new(bootshim_params),
                },
            )
        }
        SnpLinuxDirectBootLayout::AciHyperv => {
            ensure!(
                !load_info.aci_initial_import_ranges.is_empty(),
                "ACI loader did not report initial import ranges"
            );
            ensure!(
                processor_count as usize <= SNP_ACI_IGVM_MAX_VPS,
                "ACI IGVM supports at most {SNP_ACI_IGVM_MAX_VPS} VPs"
            );
            let mut topology_config = SnpAciIgvmConfig::new_zeroed();
            topology_config.magic = SNP_ACI_IGVM_CONFIG_MAGIC;
            topology_config.version = SNP_ACI_IGVM_CONFIG_VERSION;
            topology_config.vp_count = processor_count;
            let expected_apic_ids = processor_topology
                .vps_arch()
                .map(|vp| vp.apic_id)
                .collect::<Vec<_>>();
            for vp in processor_topology.vps_arch() {
                topology_config.apic_ids[vp.base.vp_index.index() as usize] = vp.apic_id;
            }
            importer
                .import_pages(
                    loader::linux::ACI_IGVM_CONFIG_BASE / PAGE_SIZE,
                    1,
                    "linux-aci-igvm-config",
                    BootPageAcceptance::Exclusive,
                    topology_config.as_bytes(),
                )
                .context("importing ACI IGVM topology config")?;
            importer.complete_initial_ranges(&load_info.aci_initial_import_ranges)?;
            let vmsa_gpa = importer.vmsa_gpa()?;
            let [parameter_area] = importer.parameter_areas.as_slice() else {
                bail!("ACI loader did not create exactly one IGVM parameter area");
            };
            (
                Vec::new(),
                VmsaDirectiveConfig {
                    gpa: vmsa_gpa,
                    context_count: 1,
                },
                ExpectedBootLayout::AciHyperv {
                    linux_entry,
                    linux_zero_page,
                    vmsa_gpa,
                    parameter_gpa: parameter_area.page_base * PAGE_SIZE,
                    expected_apic_ids,
                },
            )
        }
    };
    let explicit_pages = importer.pages.keys().copied().collect::<BTreeSet<_>>();
    let (mut directives, _vmsa, map) =
        importer.finish(injection_type, &bootshim_ranges, vmsa_config)?;
    let policy: u64 = policy.into();
    let platform_headers = vec![IgvmPlatformHeader::SupportedPlatform(
        IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: COMPATIBILITY_MASK,
            highest_vtl: 0,
            platform_type: IgvmPlatformType::SEV_SNP,
            platform_version: igvm_defs::IGVM_SEV_SNP_PLATFORM_VERSION,
            shared_gpa_boundary: 0,
        },
    )];
    let initialization_headers = vec![IgvmInitializationHeader::GuestPolicy {
        policy,
        compatibility_mask: COMPATIBILITY_MASK,
    }];

    let launch_digest = generate_snp_measurement(
        &initialization_headers,
        &mut directives,
        guest_svn,
        SnpImageIdentity::LINUX_DIRECT,
    )
    .context("computing SNP launch digest")?;

    let igvm = IgvmFile::new(
        IgvmRevision::V1,
        platform_headers,
        initialization_headers,
        directives,
    )
    .context("constructing IGVM")?;
    let mut binary = Vec::new();
    igvm.serialize(&mut binary).context("serializing IGVM")?;
    let reparsed = IgvmFile::new_from_binary(&binary, Some(igvm::IsolationType::Snp))
        .context("validating serialized SNP IGVM")?;
    validate_generated_igvm(
        &reparsed,
        launch_digest,
        policy,
        guest_svn,
        injection_type,
        processor_count,
        memory_page_count,
        1u64 << c_bit_position,
        &expected_boot_layout,
        &explicit_pages,
    )?;

    Ok(BuildOutput {
        guest: igvm,
        map,
        measurement: Measurement::Snp(SnpMeasurement::new(
            launch_digest,
            guest_svn,
            SnpPolicy::from(policy).debug() == 1,
        )),
    })
}

fn validate_plan(plan: &VmLayoutPlan) -> Result<(), ConfigError> {
    if plan.node_mem_sizes.len() != 1 {
        return Err(ConfigError::Numa(plan.node_mem_sizes.len()));
    }
    if plan.vtl2_layout.is_some() {
        return Err(ConfigError::Vtl2);
    }
    if plan.layout.vtl2_chipset_mmio_size != 0 {
        return Err(ConfigError::Vtl2ChipsetMmio);
    }
    if plan.vtl2_framebuffer_size != 0 {
        return Err(ConfigError::Framebuffer);
    }
    if plan.virtio_mmio_count != 0 {
        return Err(ConfigError::VirtioMmio);
    }
    if !plan.pcie_root_complexes.is_empty() && !plan.pcie_ecam_below_4gb {
        return Err(ConfigError::HighPcieEcam);
    }
    for root_complex in &plan.pcie_root_complexes {
        if root_complex.cxl.is_some() {
            return Err(ConfigError::Cxl(root_complex.name.clone()));
        }
        if root_complex.iommu.is_some() {
            return Err(ConfigError::Iommu(root_complex.name.clone()));
        }
    }
    Ok(())
}

fn resolve_c_bit_position(c_bit_position: Option<u8>) -> Result<u8, ConfigError> {
    c_bit_position
        .or_else(host_snp_c_bit_position)
        .ok_or(ConfigError::MissingHostCBit)
}

#[cfg(target_arch = "x86_64")] // xtask-fmt allow-target-arch cpu-intrinsic
fn host_snp_c_bit_position() -> Option<u8> {
    snp_c_bit_from_cpuid(|function, subfunction| {
        let result = safe_intrinsics::cpuid(function, subfunction);
        [result.eax, result.ebx, result.ecx, result.edx]
    })
}

#[cfg(not(target_arch = "x86_64"))] // xtask-fmt allow-target-arch cpu-intrinsic
fn host_snp_c_bit_position() -> Option<u8> {
    None
}

#[cfg(any(target_arch = "x86_64", test))] // xtask-fmt allow-target-arch cpu-intrinsic
fn snp_c_bit_from_cpuid(mut cpuid: impl FnMut(u32, u32) -> [u32; 4]) -> Option<u8> {
    let max_extended = cpuid(CpuidFunction::ExtendedMaxFunction.0, 0)[0];
    if max_extended < CpuidFunction::ExtendedSevFeatures.0 {
        return None;
    }

    let [eax, ebx, _, _] = cpuid(CpuidFunction::ExtendedSevFeatures.0, 0);
    ExtendedSevFeaturesEax::from(eax)
        .sev_snp()
        .then(|| ExtendedSevFeaturesEbx::from(ebx).cbit_position())
}

fn align_up_to_page(value: u64) -> anyhow::Result<u64> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
        .context("page alignment overflow")
}

fn build_bootshim_params(
    linux_entry: u64,
    linux_zero_page: u64,
    ram_end: u64,
    ranges: &[SnpBootShimRange],
) -> anyhow::Result<SnpBootShimParams> {
    ensure!(
        ranges.len() <= SNP_BOOT_SHIM_MAX_RANGES,
        "sparse SNP layout requires {} bootshim ranges, but the parameter page supports at most {}",
        ranges.len(),
        SNP_BOOT_SHIM_MAX_RANGES
    );
    let mut params = SnpBootShimParams::new_zeroed();
    params.magic = SNP_BOOT_SHIM_PARAMS_MAGIC;
    params.version = SNP_BOOT_SHIM_PARAMS_VERSION;
    params.range_count = ranges
        .len()
        .try_into()
        .context("SNP bootshim range count does not fit in u32")?;
    params.linux_entry = linux_entry;
    params.linux_zero_page = linux_zero_page;
    params.ram_end = ram_end;
    params.ranges[..ranges.len()].copy_from_slice(ranges);
    Ok(params)
}

fn validate_generated_igvm(
    igvm: &IgvmFile,
    expected_launch_digest: [u8; 48],
    expected_policy: u64,
    expected_guest_svn: u32,
    injection_type: &SnpInjectionType,
    processor_count: u32,
    ram_page_count: u64,
    c_bit_mask: u64,
    expected_boot_layout: &ExpectedBootLayout,
    expected_explicit_pages: &BTreeSet<u64>,
) -> anyhow::Result<()> {
    ensure!(igvm.platforms().len() == 1, "expected one platform header");
    let IgvmPlatformHeader::SupportedPlatform(platform) = &igvm.platforms()[0];
    ensure!(
        platform.platform_type == IgvmPlatformType::SEV_SNP
            && platform.highest_vtl == 0
            && platform.shared_gpa_boundary == 0,
        "unexpected SNP platform configuration"
    );
    ensure!(
        igvm.initializations().iter().any(|header| matches!(
            header,
            IgvmInitializationHeader::GuestPolicy {
                policy,
                compatibility_mask: COMPATIBILITY_MASK,
            } if *policy == expected_policy
        )),
        "serialized file lost its SNP guest policy"
    );

    let mut covered_pages = BTreeSet::new();
    let mut required_memory_count = 0;
    let mut next_vmsa_index = 0;
    let mut id_block_count = 0;
    let mut secrets_count = 0;
    let mut cpuid_count = 0;
    let mut saw_vmsa = false;
    let mut serialized_params = None;
    let mut parameter_area_count = 0;
    let mut vp_count_parameter_count = 0;
    let mut memory_map_parameter_count = 0;
    let mut parameter_insert_count = 0;
    let mut serialized_topology = None;
    let (expected_vmsa_gpa, expected_vmsa_count, expected_entry, expected_rsi) =
        match expected_boot_layout {
            ExpectedBootLayout::Standard {
                shim_entry,
                params_gpa,
                ..
            } => (KVM_VMSA_GPA, processor_count, *shim_entry, *params_gpa),
            ExpectedBootLayout::AciHyperv {
                linux_entry,
                linux_zero_page,
                vmsa_gpa,
                ..
            } => (*vmsa_gpa, 1, *linux_entry, *linux_zero_page),
        };

    for directive in igvm.directives() {
        match directive {
            IgvmDirectiveHeader::PageData {
                gpa,
                flags,
                data_type,
                data,
                ..
            } => {
                ensure!(!saw_vmsa, "PageData appears after the VMSA directive");
                ensure!(gpa.is_multiple_of(PAGE_SIZE), "unaligned PageData GPA");
                let page = gpa / PAGE_SIZE;
                ensure!(page < ram_page_count, "PageData lies outside RAM");
                ensure!(
                    covered_pages.insert(page),
                    "duplicate page directive at GPA {gpa:#x}"
                );
                ensure!(
                    !flags.shared() && !flags.unmeasured(),
                    "fixed image unexpectedly contains shared or unmeasured PageData"
                );
                ensure!(
                    data.len() <= PAGE_SIZE as usize,
                    "PageData exceeds one page"
                );
                if *data_type == IgvmPageDataType::SECRETS {
                    secrets_count += 1;
                } else if *data_type == IgvmPageDataType::CPUID_DATA {
                    cpuid_count += 1;
                } else {
                    ensure!(
                        *data_type == IgvmPageDataType::NORMAL,
                        "unexpected PageData type {data_type:?}"
                    );
                }
                if matches!(
                    expected_boot_layout,
                    ExpectedBootLayout::Standard { params_gpa, .. } if *gpa == *params_gpa
                ) {
                    let mut params_page = [0; PAGE_SIZE as usize];
                    params_page[..data.len()].copy_from_slice(data);
                    let params = SnpBootShimParams::read_from_bytes(&params_page)
                        .map_err(|_| anyhow::anyhow!("invalid SNP bootshim parameter page"))?;
                    serialized_params = Some(params);
                }
                if *gpa == loader::linux::ACI_IGVM_CONFIG_BASE {
                    ensure!(
                        matches!(expected_boot_layout, ExpectedBootLayout::AciHyperv { .. }),
                        "standard layout unexpectedly contains an ACI topology contract"
                    );
                    serialized_topology = Some(
                        SnpAciIgvmConfig::read_from_bytes(data)
                            .map_err(|_| anyhow::anyhow!("invalid ACI topology contract page"))?,
                    );
                }
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                vp_index,
                vmsa,
                ..
            } => {
                ensure!(*gpa == expected_vmsa_gpa, "VMSA is not at the expected GPA");
                ensure!(
                    u32::from(*vp_index) == next_vmsa_index,
                    "VMSA VP contexts are not ordered by VP index"
                );
                validate_vmsa_features(vmsa.sev_features, injection_type)?;
                ensure!(vmsa.virtual_tom == 0, "VMSA virtual TOM is not zero");
                ensure!(
                    vmsa.cr3 & c_bit_mask != 0,
                    "VMSA CR3 does not contain the configured C-bit"
                );
                ensure!(
                    vmsa.rip == expected_entry,
                    "VMSA does not enter the expected boot target"
                );
                ensure!(
                    vmsa.rsi == expected_rsi,
                    "VMSA does not point RSI at the expected boot parameters"
                );
                ensure!(
                    vmsa.cr0 & x86defs::X64_CR0_ET != 0,
                    "VMSA CR0 does not contain KVM's forced ET bit"
                );
                ensure!(
                    vmsa.cr4 & x86defs::X64_CR4_MCE != 0,
                    "VMSA CR4 does not contain KVM's forced MCE bit"
                );
                ensure!(
                    vmsa.rflags == u64::from(x86defs::RFlags::at_reset()),
                    "VMSA RFLAGS does not match KVM reset state"
                );
                ensure!(
                    vmsa.dr6 == 0xffff_0ff0 && vmsa.dr7 == 0x400,
                    "VMSA debug registers do not match KVM reset state"
                );
                ensure!(
                    vmsa.x87_fcw == x86defs::xsave::INIT_FCW
                        && vmsa.mxcsr == x86defs::xsave::DEFAULT_MXCSR,
                    "VMSA FPU control state does not match KVM reset state"
                );
                next_vmsa_index += 1;
                saw_vmsa = true;
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data,
            } => {
                ensure!(
                    matches!(expected_boot_layout, ExpectedBootLayout::AciHyperv { .. }),
                    "standard layout unexpectedly contains a parameter area"
                );
                ensure!(
                    *number_of_bytes == PAGE_SIZE
                        && *parameter_area_index == 0
                        && initial_data.is_empty(),
                    "unexpected ACI parameter area"
                );
                parameter_area_count += 1;
            }
            IgvmDirectiveHeader::VpCount(info) => {
                ensure!(
                    matches!(expected_boot_layout, ExpectedBootLayout::AciHyperv { .. })
                        && info.parameter_area_index == 0
                        && info.byte_offset == 0,
                    "unexpected ACI VP-count parameter"
                );
                vp_count_parameter_count += 1;
            }
            IgvmDirectiveHeader::MemoryMap(info) => {
                ensure!(
                    matches!(expected_boot_layout, ExpectedBootLayout::AciHyperv { .. })
                        && info.parameter_area_index == 0
                        && info.byte_offset == loader::linux::ACI_MEMORY_MAP_OFFSET as u32,
                    "unexpected ACI memory-map parameter"
                );
                memory_map_parameter_count += 1;
            }
            IgvmDirectiveHeader::ParameterInsert(info) => {
                let ExpectedBootLayout::AciHyperv { parameter_gpa, .. } = expected_boot_layout
                else {
                    bail!("standard layout unexpectedly contains a parameter insert");
                };
                ensure!(
                    info.gpa == *parameter_gpa && info.parameter_area_index == 0,
                    "unexpected ACI parameter insertion"
                );
                parameter_insert_count += 1;
            }
            IgvmDirectiveHeader::RequiredMemory {
                gpa,
                number_of_bytes,
                vtl2_protectable,
                ..
            } => {
                ensure!(
                    *gpa == 0
                        && u64::from(*number_of_bytes) == ram_page_count * PAGE_SIZE
                        && !vtl2_protectable,
                    "unexpected RequiredMemory directive"
                );
                required_memory_count += 1;
            }
            IgvmDirectiveHeader::SnpIdBlock { ld, guest_svn, .. } => {
                ensure!(
                    *ld == expected_launch_digest && *guest_svn == expected_guest_svn,
                    "SNP ID block does not match the generated launch digest"
                );
                id_block_count += 1;
            }
            unexpected => bail!("unexpected directive in fixed SNP IGVM: {unexpected:?}"),
        }
    }

    ensure!(
        &covered_pages == expected_explicit_pages,
        "serialized IGVM explicit page set changed"
    );
    match expected_boot_layout {
        ExpectedBootLayout::Standard { params, .. } => {
            let serialized_params =
                serialized_params.context("SNP bootshim parameter page is missing")?;
            ensure!(
                &serialized_params == params.as_ref(),
                "serialized SNP bootshim parameters changed"
            );
            let range_count = usize::try_from(serialized_params.range_count)
                .context("SNP bootshim range count does not fit in usize")?;
            let ranges = serialized_params
                .ranges
                .get(..range_count)
                .context("SNP bootshim range count exceeds the parameter-page capacity")?;
            let mut complete_ram = covered_pages.clone();
            let mut previous_end = 0;
            for range in ranges {
                ensure!(range.page_count != 0, "empty SNP bootshim acceptance range");
                let end = range
                    .start_gpn
                    .checked_add(range.page_count)
                    .context("SNP bootshim acceptance range overflow")?;
                ensure!(
                    range.start_gpn >= previous_end && end <= ram_page_count,
                    "invalid SNP bootshim acceptance range"
                );
                for page in range.start_gpn..end {
                    ensure!(
                        complete_ram.insert(page),
                        "SNP bootshim acceptance range overlaps an explicit page"
                    );
                }
                previous_end = end;
            }
            ensure!(
                complete_ram.len() == ram_page_count as usize
                    && complete_ram.first() == Some(&0)
                    && complete_ram.last() == Some(&(ram_page_count - 1)),
                "explicit and bootshim-accepted ranges do not cover all required RAM"
            );
            ensure!(
                parameter_area_count == 0
                    && vp_count_parameter_count == 0
                    && memory_map_parameter_count == 0
                    && parameter_insert_count == 0,
                "standard layout unexpectedly contains IGVM parameters"
            );
        }
        ExpectedBootLayout::AciHyperv {
            expected_apic_ids, ..
        } => {
            ensure!(
                serialized_params.is_none(),
                "ACI layout unexpectedly contains bootshim parameters"
            );
            ensure!(
                parameter_area_count == 1
                    && vp_count_parameter_count == 1
                    && memory_map_parameter_count == 1
                    && parameter_insert_count == 1,
                "ACI layout does not contain the expected runtime parameters"
            );
            let topology = serialized_topology.context("ACI topology contract page is missing")?;
            ensure!(
                topology.magic == SNP_ACI_IGVM_CONFIG_MAGIC
                    && topology.version == SNP_ACI_IGVM_CONFIG_VERSION
                    && topology.vp_count as usize == expected_apic_ids.len()
                    && topology.apic_ids[..expected_apic_ids.len()] == *expected_apic_ids
                    && topology.reserved.iter().all(|&value| value == 0),
                "serialized ACI topology contract changed"
            );
            ensure!(
                covered_pages.len() < ram_page_count as usize,
                "ACI layout unexpectedly imports all guest RAM"
            );
        }
    }
    ensure!(required_memory_count == 1, "expected one RequiredMemory");
    ensure!(
        next_vmsa_index == expected_vmsa_count,
        "unexpected SNP VMSA context count"
    );
    ensure!(id_block_count == 1, "expected one SNP ID block");
    ensure!(secrets_count == 1, "expected one SNP secrets page");
    ensure!(cpuid_count == 1, "expected one SNP CPUID page");

    let mut measured_directives = igvm
        .directives()
        .iter()
        .filter(|directive| !matches!(directive, IgvmDirectiveHeader::SnpIdBlock { .. }))
        .cloned()
        .collect();
    let measured_digest = generate_snp_measurement(
        igvm.initializations(),
        &mut measured_directives,
        expected_guest_svn,
        SnpImageIdentity::LINUX_DIRECT,
    )
    .context("remeasuring serialized SNP IGVM")?;
    ensure!(
        measured_digest == expected_launch_digest,
        "serialized IGVM launch digest changed"
    );
    Ok(())
}

fn expected_vmsa_features(injection_type: &SnpInjectionType) -> SevFeatures {
    SevFeatures::new()
        .with_snp(true)
        .with_restrict_injection(matches!(injection_type, SnpInjectionType::Restricted))
}

fn validate_vmsa_features(
    features: SevFeatures,
    injection_type: &SnpInjectionType,
) -> anyhow::Result<()> {
    let expected_restricted = matches!(injection_type, SnpInjectionType::Restricted);
    ensure!(
        features.restrict_injection() == expected_restricted,
        "VMSA restricted-injection feature does not match the configured injection type"
    );

    let expected = u64::from(expected_vmsa_features(injection_type));
    let actual = u64::from(features);
    ensure!(
        actual == expected,
        "unexpected VMSA SEV feature combination: expected {expected:#x}, found {actual:#x}"
    );
    Ok(())
}

fn build_vmsa(
    registers: &[X86Register],
    c_bit_mask: u64,
    injection_type: &SnpInjectionType,
) -> anyhow::Result<SevVmsa> {
    let mut vmsa = SevVmsa::new_zeroed();
    vmsa.efer = x86defs::X64_EFER_SVME;
    vmsa.sev_features = expected_vmsa_features(injection_type);
    vmsa.virtual_tom = 0;
    vmsa.xcr0 = 1;
    vmsa.rflags = u64::from(x86defs::RFlags::at_reset());
    vmsa.dr6 = 0xffff_0ff0;
    vmsa.dr7 = 0x400;
    vmsa.tr = segment_selector(SegmentRegister {
        base: 0,
        limit: 0xffff,
        selector: 0,
        attributes: 0x8b,
    });
    vmsa.ldtr = segment_selector(SegmentRegister {
        base: 0,
        limit: 0xffff,
        selector: 0,
        attributes: 0x82,
    });
    vmsa.idtr = table_selector(TableRegister {
        base: 0,
        limit: 0xffff,
    });
    vmsa.x87_fcw = x86defs::xsave::INIT_FCW;
    vmsa.mxcsr = x86defs::xsave::DEFAULT_MXCSR;

    for &register in registers {
        match register {
            X86Register::Gdtr(value) => vmsa.gdtr = table_selector(value),
            X86Register::Idtr(value) => vmsa.idtr = table_selector(value),
            X86Register::Ds(value) => vmsa.ds = segment_selector(value),
            X86Register::Es(value) => vmsa.es = segment_selector(value),
            X86Register::Fs(value) => vmsa.fs = segment_selector(value),
            X86Register::Gs(value) => vmsa.gs = segment_selector(value),
            X86Register::Ss(value) => vmsa.ss = segment_selector(value),
            X86Register::Cs(value) => vmsa.cs = segment_selector(value),
            X86Register::Tr(value) => vmsa.tr = segment_selector(value),
            X86Register::Cr0(value) => vmsa.cr0 = value | x86defs::X64_CR0_ET,
            X86Register::Cr3(value) => vmsa.cr3 = value | c_bit_mask,
            X86Register::Cr4(value) => vmsa.cr4 = value | x86defs::X64_CR4_MCE,
            X86Register::Efer(value) => vmsa.efer = value | x86defs::X64_EFER_SVME,
            X86Register::Pat(value) => vmsa.pat = value,
            X86Register::Rbp(value) => vmsa.rbp = value,
            X86Register::Rip(value) => vmsa.rip = value,
            X86Register::Rsi(value) => vmsa.rsi = value,
            X86Register::Rsp(value) => vmsa.rsp = value,
            X86Register::R8(value) => vmsa.r8 = value,
            X86Register::R9(value) => vmsa.r9 = value,
            X86Register::R10(value) => vmsa.r10 = value,
            X86Register::R11(value) => vmsa.r11 = value,
            X86Register::R12(value) => vmsa.r12 = value,
            X86Register::Rflags(value) => vmsa.rflags = value,
            X86Register::MtrrDefType(_)
            | X86Register::MtrrPhysBase0(_)
            | X86Register::MtrrPhysMask0(_)
            | X86Register::MtrrPhysBase1(_)
            | X86Register::MtrrPhysMask1(_)
            | X86Register::MtrrPhysBase2(_)
            | X86Register::MtrrPhysMask2(_)
            | X86Register::MtrrPhysBase3(_)
            | X86Register::MtrrPhysMask3(_)
            | X86Register::MtrrPhysBase4(_)
            | X86Register::MtrrPhysMask4(_)
            | X86Register::MtrrFix64k00000(_)
            | X86Register::MtrrFix16k80000(_)
            | X86Register::MtrrFix4kE0000(_)
            | X86Register::MtrrFix4kE8000(_)
            | X86Register::MtrrFix4kF0000(_)
            | X86Register::MtrrFix4kF8000(_) => {}
        }
    }

    ensure!(vmsa.rip != 0, "Linux loader did not provide an entry point");
    ensure!(
        vmsa.cr3 & c_bit_mask != 0,
        "initial CR3 does not contain the fixed SNP C-bit"
    );
    ensure!(
        !vmsa.sev_features.vtom(),
        "C-bit image must not enable vTOM"
    );
    Ok(vmsa)
}

fn table_selector(value: TableRegister) -> SevSelector {
    SevSelector {
        selector: 0,
        attrib: 0,
        limit: value.limit.into(),
        base: value.base,
    }
}

fn segment_selector(value: SegmentRegister) -> SevSelector {
    SevSelector {
        selector: value.selector,
        attrib: (value.attributes & 0xff) | ((value.attributes >> 4) & 0xf00),
        limit: value.limit,
        base: value.base,
    }
}

struct MapEntry {
    start_page: u64,
    page_count: u64,
    tag: String,
    kind: &'static str,
}

fn build_sparse_ram_directives(
    imported: &BTreeMap<u64, ImportedPage>,
    parameter_areas: &[IgvmParameterArea],
    vmsa: &SevVmsa,
    vmsa_config: VmsaDirectiveConfig,
    ram_page_count: u64,
    bootshim_ranges: &[SnpBootShimRange],
) -> anyhow::Result<(Vec<IgvmDirectiveHeader>, String)> {
    let mut directives = Vec::new();
    let mut memory_directives = BTreeMap::new();
    let mut map_entries = Vec::new();

    for (&page, imported) in imported {
        let (data_type, flags, kind) = page_data_shape(imported.acceptance)?;
        memory_directives.insert(
            page,
            IgvmDirectiveHeader::PageData {
                gpa: page * PAGE_SIZE,
                compatibility_mask: COMPATIBILITY_MASK,
                flags,
                data_type,
                data: imported.data.clone(),
            },
        );
        map_entries.push(MapEntry {
            start_page: page,
            page_count: 1,
            tag: imported.tag.to_owned(),
            kind,
        });
    }
    for (index, area) in parameter_areas.iter().enumerate() {
        let parameter_area_index = index
            .try_into()
            .context("IGVM parameter area index does not fit in u32")?;
        directives.push(IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: u64::from(area.page_count) * PAGE_SIZE,
            parameter_area_index,
            initial_data: area.initial_data.clone(),
        });
        for &(byte_offset, parameter_type) in &area.parameters {
            let info = IGVM_VHS_PARAMETER {
                parameter_area_index,
                byte_offset,
            };
            directives.push(match parameter_type {
                IgvmParameterType::VpCount => IgvmDirectiveHeader::VpCount(info),
                IgvmParameterType::MemoryMap => IgvmDirectiveHeader::MemoryMap(info),
                unsupported => bail!("unsupported ACI IGVM parameter type {unsupported:?}"),
            });
        }
        ensure!(
            memory_directives
                .insert(
                    area.page_base,
                    IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
                        gpa: area.page_base * PAGE_SIZE,
                        compatibility_mask: COMPATIBILITY_MASK,
                        parameter_area_index,
                    }),
                )
                .is_none(),
            "parameter area overlaps an existing directive at GPA {:#x}",
            area.page_base * PAGE_SIZE
        );
        map_entries.push(MapEntry {
            start_page: area.page_base,
            page_count: u64::from(area.page_count),
            tag: area.tag.clone(),
            kind: "PARAMETER",
        });
    }
    directives.extend(memory_directives.into_values());
    for range in bootshim_ranges {
        map_entries.push(MapEntry {
            start_page: range.start_gpn,
            page_count: range.page_count,
            tag: "snp-bootshim-accepted-ram".to_owned(),
            kind: "PVALIDATE",
        });
    }
    for vp_index in 0..vmsa_config.context_count {
        directives.push(IgvmDirectiveHeader::SnpVpContext {
            gpa: vmsa_config.gpa,
            compatibility_mask: COMPATIBILITY_MASK,
            vp_index: vp_index
                .try_into()
                .context("VP index does not fit in IGVM")?,
            vmsa: Box::new(*vmsa),
        });
        map_entries.push(MapEntry {
            start_page: vmsa_config.gpa / PAGE_SIZE,
            page_count: 1,
            tag: format!("snp-vmsa-vp{vp_index}"),
            kind: "VMSA",
        });
    }

    ensure!(
        imported.keys().all(|page| *page < ram_page_count),
        "an imported page lies outside RAM"
    );
    let parameter_page_count = parameter_areas
        .iter()
        .map(|area| u64::from(area.page_count))
        .sum::<u64>();
    let bootshim_page_count = bootshim_ranges.iter().map(|range| range.page_count).sum();
    Ok((
        directives,
        format_map(
            map_entries,
            ram_page_count,
            imported.len() as u64 + parameter_page_count,
            bootshim_page_count,
        ),
    ))
}

fn page_data_shape(
    acceptance: BootPageAcceptance,
) -> anyhow::Result<(IgvmPageDataType, IgvmPageDataFlags, &'static str)> {
    Ok(match acceptance {
        BootPageAcceptance::Exclusive => {
            (IgvmPageDataType::NORMAL, IgvmPageDataFlags::new(), "NORMAL")
        }
        BootPageAcceptance::ExclusiveUnmeasured => (
            IgvmPageDataType::NORMAL,
            IgvmPageDataFlags::new().with_unmeasured(true),
            "UNMEASURED",
        ),
        BootPageAcceptance::SecretsPage => (
            IgvmPageDataType::SECRETS,
            IgvmPageDataFlags::new(),
            "SECRETS",
        ),
        BootPageAcceptance::CpuidPage => (
            IgvmPageDataType::CPUID_DATA,
            IgvmPageDataFlags::new(),
            "CPUID",
        ),
        BootPageAcceptance::CpuidExtendedStatePage => (
            IgvmPageDataType::CPUID_XF,
            IgvmPageDataFlags::new(),
            "CPUID_XF",
        ),
        BootPageAcceptance::Shared => (
            IgvmPageDataType::NORMAL,
            IgvmPageDataFlags::new().with_shared(true),
            "SHARED",
        ),
        BootPageAcceptance::VpContext => {
            bail!("VP context must be emitted as SnpVpContext")
        }
    })
}

fn format_map(
    mut entries: Vec<MapEntry>,
    ram_page_count: u64,
    imported_page_count: u64,
    bootshim_page_count: u64,
) -> String {
    let ram_size = ram_page_count * PAGE_SIZE;
    let mut output = format!(
        "IGVM file isolation: SNP (C-bit model)\n\
         Required memory: 0000000000000000 - {ram_size:016x} ({ram_size:#x} bytes)\n\
         Measured/imported RAM: {:#x} pages ({:#x} bytes)\n\
         Bootshim-accepted RAM: {:#x} pages ({:#x} bytes)\n\
         IGVM file layout:\n",
        imported_page_count,
        imported_page_count * PAGE_SIZE,
        bootshim_page_count,
        bootshim_page_count * PAGE_SIZE,
    );
    entries.sort_by_key(|entry| entry.start_page);
    let mut index = 0;
    while index < entries.len() {
        let entry = &entries[index];
        let start_page = entry.start_page;
        let mut end_page = entry.start_page + entry.page_count;
        let mut end = index + 1;
        while end < entries.len()
            && entries[end].start_page == end_page
            && entries[end].tag == entry.tag
            && entries[end].kind == entry.kind
        {
            end_page += entries[end].page_count;
            end += 1;
        }
        let _ = writeln!(
            output,
            "  {:016x} - {:016x} ({:#x} bytes) {} [{}]",
            start_page * PAGE_SIZE,
            end_page * PAGE_SIZE,
            (end_page - start_page) * PAGE_SIZE,
            entry.tag,
            entry.kind
        );
        index = end;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvmm_vm_layout::LayoutPlan;
    use openvmm_vm_layout::PcieIommuPlan;
    use openvmm_vm_layout::PcieMmioRangePlan;
    use openvmm_vm_layout::PcieRootComplexPlan;
    use test_with_tracing::test;

    const TEST_C_BIT_MASK: u64 = 1 << 51;

    fn test_plan() -> VmLayoutPlan {
        VmLayoutPlan {
            node_mem_sizes: vec![160 * 1024 * 1024],
            layout: LayoutPlan {
                chipset_low_mmio_size: 128 * 1024 * 1024,
                chipset_high_mmio_size: 0,
                vtl2_chipset_mmio_size: 0,
            },
            pcie_root_complexes: vec![PcieRootComplexPlan {
                index: 0,
                name: "s0rc0".to_string(),
                segment: 0,
                start_bus: 0,
                end_bus: 255,
                low_mmio: PcieMmioRangePlan::Dynamic {
                    size: 64 * 1024 * 1024,
                },
                high_mmio: PcieMmioRangePlan::Dynamic {
                    size: 1024 * 1024 * 1024,
                },
                cxl: None,
                iommu: None,
                vnode: None,
                preserve_bars: false,
            }],
            virtio_mmio_count: 0,
            pcie_ecam_below_4gb: true,
            vtl2_layout: None,
            ram_start_address: 0,
            vtl2_framebuffer_size: 0,
            physical_address_size: 48,
        }
    }

    #[test]
    fn explicit_c_bit_overrides_host_detection() {
        assert_eq!(resolve_c_bit_position(Some(47)).unwrap(), 47);
    }

    #[test]
    fn detects_host_c_bit_from_cpuid_shape() {
        let cpuid = |function, _| match CpuidFunction(function) {
            CpuidFunction::ExtendedMaxFunction => [CpuidFunction::ExtendedSevFeatures.0, 0, 0, 0],
            CpuidFunction::ExtendedSevFeatures => [
                ExtendedSevFeaturesEax::new().with_sev_snp(true).into(),
                ExtendedSevFeaturesEbx::new().with_cbit_position(51).into(),
                0,
                0,
            ],
            _ => [0; 4],
        };
        assert_eq!(snp_c_bit_from_cpuid(cpuid), Some(51));
    }

    #[test]
    fn rejects_unsupported_layout_features() {
        let mut plan = test_plan();
        plan.node_mem_sizes.push(4096);
        assert!(matches!(validate_plan(&plan), Err(ConfigError::Numa(2))));

        let mut plan = test_plan();
        plan.virtio_mmio_count = 1;
        assert!(matches!(validate_plan(&plan), Err(ConfigError::VirtioMmio)));

        let mut plan = test_plan();
        plan.pcie_root_complexes[0].iommu = Some(PcieIommuPlan::AmdVi);
        assert!(matches!(validate_plan(&plan), Err(ConfigError::Iommu(_))));
    }

    fn test_vmsa(injection_type: &SnpInjectionType) -> SevVmsa {
        build_vmsa(
            &[
                X86Register::Rip(0x100000),
                X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
                X86Register::Cr0(x86defs::X64_CR0_PE | x86defs::X64_CR0_PG),
                X86Register::Cr4(x86defs::X64_CR4_PAE),
                X86Register::Efer(x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA),
            ],
            TEST_C_BIT_MASK,
            injection_type,
        )
        .unwrap()
    }

    fn remeasure_vmsa(injection_type: &SnpInjectionType) -> [u8; 48] {
        let initialization_headers = vec![IgvmInitializationHeader::GuestPolicy {
            policy: 196608,
            compatibility_mask: COMPATIBILITY_MASK,
        }];
        let mut directives = vec![IgvmDirectiveHeader::SnpVpContext {
            gpa: KVM_VMSA_GPA,
            compatibility_mask: COMPATIBILITY_MASK,
            vp_index: 0,
            vmsa: Box::new(test_vmsa(injection_type)),
        }];
        let expected = generate_snp_measurement(
            &initialization_headers,
            &mut directives,
            1,
            SnpImageIdentity::LINUX_DIRECT,
        )
        .unwrap();
        let igvm = IgvmFile::new(
            IgvmRevision::V1,
            vec![IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: COMPATIBILITY_MASK,
                    highest_vtl: 0,
                    platform_type: IgvmPlatformType::SEV_SNP,
                    platform_version: igvm_defs::IGVM_SEV_SNP_PLATFORM_VERSION,
                    shared_gpa_boundary: 0,
                },
            )],
            initialization_headers,
            directives,
        )
        .unwrap();
        let mut binary = Vec::new();
        igvm.serialize(&mut binary).unwrap();
        let reparsed = IgvmFile::new_from_binary(&binary, Some(igvm::IsolationType::Snp)).unwrap();
        let parsed_vmsa = reparsed
            .directives()
            .iter()
            .find_map(|directive| match directive {
                IgvmDirectiveHeader::SnpVpContext { vmsa, .. } => Some(vmsa),
                _ => None,
            })
            .unwrap();
        validate_vmsa_features(parsed_vmsa.sev_features, injection_type).unwrap();

        let mut measured_directives = reparsed
            .directives()
            .iter()
            .filter(|directive| !matches!(directive, IgvmDirectiveHeader::SnpIdBlock { .. }))
            .cloned()
            .collect();
        let actual = generate_snp_measurement(
            reparsed.initializations(),
            &mut measured_directives,
            1,
            SnpImageIdentity::LINUX_DIRECT,
        )
        .unwrap();
        assert_eq!(actual, expected);
        actual
    }

    #[test]
    fn normal_vmsa_uses_c_bit_model() {
        let vmsa = test_vmsa(&SnpInjectionType::Normal);
        assert_eq!(vmsa.rip, 0x100000);
        assert_ne!(vmsa.cr3 & TEST_C_BIT_MASK, 0);
        assert_ne!(vmsa.cr0 & x86defs::X64_CR0_ET, 0);
        assert_ne!(vmsa.cr4 & x86defs::X64_CR4_MCE, 0);
        assert!(vmsa.sev_features.snp());
        assert!(!vmsa.sev_features.vtom());
        assert!(!vmsa.sev_features.restrict_injection());
        assert!(!vmsa.sev_features.alternate_injection());
        assert!(!vmsa.sev_features.debug_swap());
        assert_eq!(
            u64::from(vmsa.sev_features),
            u64::from(expected_vmsa_features(&SnpInjectionType::Normal))
        );
        assert_eq!(vmsa.virtual_tom, 0);
        assert_eq!(vmsa.rflags, 2);
        assert_eq!(vmsa.dr6, 0xffff_0ff0);
        assert_eq!(vmsa.dr7, 0x400);
        assert_eq!(vmsa.tr.limit, 0xffff);
        assert_eq!(vmsa.tr.attrib, 0x8b);
        assert_eq!(vmsa.ldtr.limit, 0xffff);
        assert_eq!(vmsa.ldtr.attrib, 0x82);
        assert_eq!(vmsa.idtr.limit, 0xffff);
        assert_eq!(vmsa.x87_fcw, x86defs::xsave::INIT_FCW);
        assert_eq!(vmsa.mxcsr, x86defs::xsave::DEFAULT_MXCSR);
    }

    #[test]
    fn restricted_vmsa_uses_restrict_injection_feature() {
        let vmsa = test_vmsa(&SnpInjectionType::Restricted);

        assert!(vmsa.sev_features.snp());
        assert!(vmsa.sev_features.restrict_injection());
        assert!(!vmsa.sev_features.alternate_injection());
        assert_eq!(
            u64::from(vmsa.sev_features),
            u64::from(expected_vmsa_features(&SnpInjectionType::Restricted))
        );
    }

    #[test]
    fn validation_rejects_unexpected_injection_features() {
        let alternate_only = SevFeatures::new()
            .with_snp(true)
            .with_alternate_injection(true);
        assert!(validate_vmsa_features(alternate_only, &SnpInjectionType::Restricted).is_err());

        let combined =
            expected_vmsa_features(&SnpInjectionType::Restricted).with_alternate_injection(true);
        assert!(validate_vmsa_features(combined, &SnpInjectionType::Restricted).is_err());
    }

    #[test]
    fn normal_and_restricted_vmsa_remeasure_stably() {
        let normal = remeasure_vmsa(&SnpInjectionType::Normal);
        let restricted = remeasure_vmsa(&SnpInjectionType::Restricted);

        assert_ne!(normal, restricted);
    }

    #[test]
    fn sparse_ram_emits_only_imported_pages() {
        let mut imported = BTreeMap::new();
        imported.insert(
            1,
            ImportedPage {
                acceptance: BootPageAcceptance::SecretsPage,
                data: Vec::new(),
                tag: "secret",
            },
        );
        let vmsa = build_vmsa(
            &[
                X86Register::Rip(0x100000),
                X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            ],
            TEST_C_BIT_MASK,
            &SnpInjectionType::Normal,
        )
        .unwrap();
        let accepted_ranges = [
            SnpBootShimRange {
                start_gpn: 0,
                page_count: 1,
            },
            SnpBootShimRange {
                start_gpn: 2,
                page_count: 2,
            },
        ];
        let (directives, map) = build_sparse_ram_directives(
            &imported,
            &[],
            &vmsa,
            VmsaDirectiveConfig {
                gpa: KVM_VMSA_GPA,
                context_count: 1,
            },
            4,
            &accepted_ranges,
        )
        .unwrap();
        assert_eq!(directives.len(), 2);
        assert!(matches!(
            directives[0],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::SECRETS,
                ..
            }
        ));
        assert!(matches!(
            directives[1],
            IgvmDirectiveHeader::SnpVpContext {
                gpa: KVM_VMSA_GPA,
                ..
            }
        ));
        assert!(!map.contains("accepted-zero-ram"));
        assert!(map.contains("snp-bootshim-accepted-ram [PVALIDATE]"));
    }

    #[test]
    fn normal_sparse_ram_emits_one_vmsa_per_processor() {
        let vmsa = build_vmsa(
            &[
                X86Register::Rip(0x100000),
                X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            ],
            TEST_C_BIT_MASK,
            &SnpInjectionType::Normal,
        )
        .unwrap();
        let accepted_ranges = [SnpBootShimRange {
            start_gpn: 0,
            page_count: 1,
        }];
        let (directives, _) = build_sparse_ram_directives(
            &BTreeMap::new(),
            &[],
            &vmsa,
            VmsaDirectiveConfig {
                gpa: KVM_VMSA_GPA,
                context_count: 4,
            },
            1,
            &accepted_ranges,
        )
        .unwrap();
        let vp_indexes = directives
            .iter()
            .filter_map(|directive| match directive {
                IgvmDirectiveHeader::SnpVpContext {
                    gpa,
                    vp_index,
                    vmsa,
                    ..
                } => {
                    assert_eq!(*gpa, KVM_VMSA_GPA);
                    validate_vmsa_features(vmsa.sev_features, &SnpInjectionType::Normal).unwrap();
                    Some(*vp_index)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(vp_indexes, [0, 1, 2, 3]);
    }

    #[test]
    fn aci_layout_emits_runtime_parameters_and_one_bsp_vmsa() {
        let vmsa = build_vmsa(
            &[
                X86Register::Rip(0x1a00200),
                X86Register::Rsi(0x2000),
                X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            ],
            TEST_C_BIT_MASK,
            &SnpInjectionType::Restricted,
        )
        .unwrap();
        let parameter_areas = [IgvmParameterArea {
            page_base: 0x802,
            page_count: 1,
            initial_data: Vec::new(),
            parameters: vec![
                (0, IgvmParameterType::VpCount),
                (
                    loader::linux::ACI_MEMORY_MAP_OFFSET as u32,
                    IgvmParameterType::MemoryMap,
                ),
            ],
            tag: "linux-aci-snp-parameters".to_owned(),
        }];

        let (directives, map) = build_sparse_ram_directives(
            &BTreeMap::new(),
            &parameter_areas,
            &vmsa,
            VmsaDirectiveConfig {
                gpa: 0x201000,
                context_count: 1,
            },
            0x1000,
            &[],
        )
        .unwrap();

        assert!(matches!(
            directives[0],
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes: PAGE_SIZE,
                parameter_area_index: 0,
                ..
            }
        ));
        assert!(matches!(
            directives[1],
            IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
                parameter_area_index: 0,
                byte_offset: 0,
            })
        ));
        assert!(matches!(
            directives[2],
            IgvmDirectiveHeader::MemoryMap(IGVM_VHS_PARAMETER {
                parameter_area_index: 0,
                byte_offset,
            }) if byte_offset == loader::linux::ACI_MEMORY_MAP_OFFSET as u32
        ));
        assert!(matches!(
            directives[3],
            IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
                gpa: 0x802000,
                parameter_area_index: 0,
                ..
            })
        ));
        assert!(matches!(
            directives[4],
            IgvmDirectiveHeader::SnpVpContext {
                gpa: 0x201000,
                vp_index: 0,
                ..
            }
        ));
        assert!(map.contains("linux-aci-snp-parameters [PARAMETER]"));
        assert!(!map.contains("PVALIDATE"));
    }

    #[test]
    fn aci_initial_ranges_exclude_runtime_and_vmsa_pages() {
        let mut importer = TestIgvmImporter::new(0x1000, 51, SnpLinuxDirectBootLayout::AciHyperv);
        importer.set_vp_context_page(0x201).unwrap();
        let parameter_area = importer
            .create_parameter_area(0x802, 1, "linux-aci-snp-parameters")
            .unwrap();
        importer
            .import_parameter(parameter_area, 0, IgvmParameterType::VpCount)
            .unwrap();
        importer
            .complete_initial_ranges(&[MemoryRange::new(0x200000..0x203000)])
            .unwrap();

        assert!(importer.pages.contains_key(&0x200));
        assert!(!importer.pages.contains_key(&0x201));
        assert!(importer.pages.contains_key(&0x202));
        assert!(!importer.pages.contains_key(&0x802));
    }

    #[test]
    fn computes_coalesced_unimported_ranges() {
        let mut importer = TestIgvmImporter::new(10, 51, SnpLinuxDirectBootLayout::Standard);
        importer
            .import_pages(1, 2, "first", BootPageAcceptance::Exclusive, &[1])
            .unwrap();
        importer
            .import_pages(5, 1, "second", BootPageAcceptance::Exclusive, &[2])
            .unwrap();

        assert_eq!(
            importer.unimported_ranges([8]).unwrap(),
            [
                SnpBootShimRange {
                    start_gpn: 0,
                    page_count: 1,
                },
                SnpBootShimRange {
                    start_gpn: 3,
                    page_count: 2,
                },
                SnpBootShimRange {
                    start_gpn: 6,
                    page_count: 2,
                },
                SnpBootShimRange {
                    start_gpn: 9,
                    page_count: 1,
                },
            ]
        );
    }

    #[test]
    fn rejects_additional_import_outside_ram() {
        let importer = TestIgvmImporter::new(4, 51, SnpLinuxDirectBootLayout::Standard);
        assert!(
            importer
                .unimported_ranges([4])
                .unwrap_err()
                .to_string()
                .contains("outside RAM")
        );
    }

    #[test]
    fn rejects_too_many_bootshim_ranges() {
        let ranges = vec![
            SnpBootShimRange {
                start_gpn: 0,
                page_count: 1,
            };
            SNP_BOOT_SHIM_MAX_RANGES + 1
        ];
        assert!(
            build_bootshim_params(0x100000, 0x2000, 0x200000, &ranges)
                .unwrap_err()
                .to_string()
                .contains("supports at most")
        );
    }

    #[test]
    fn rewrites_vmsa_to_enter_bootshim() {
        let mut importer = TestIgvmImporter::new(16, 51, SnpLinuxDirectBootLayout::Standard);
        importer
            .import_vp_register(X86Register::Rip(0x100000))
            .unwrap();
        importer
            .import_vp_register(X86Register::Rsi(0x2000))
            .unwrap();
        importer
            .import_vp_register(X86Register::Cr3(0x4000))
            .unwrap();

        importer
            .replace_register(X86Register::Rip(0x80000))
            .unwrap();
        importer
            .replace_register(X86Register::Rsi(0x90000))
            .unwrap();
        let vmsa = build_vmsa(
            &importer.registers,
            TEST_C_BIT_MASK,
            &SnpInjectionType::Normal,
        )
        .unwrap();
        assert_eq!(vmsa.rip, 0x80000);
        assert_eq!(vmsa.rsi, 0x90000);
    }
}
