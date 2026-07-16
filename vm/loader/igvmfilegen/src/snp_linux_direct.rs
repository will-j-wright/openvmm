// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generation strategy for a self-contained SNP Linux-direct IGVM.

use anyhow::Context;
use anyhow::bail;
use anyhow::ensure;
use igvm::IgvmDirectiveHeader;
use igvm::IgvmFile;
use igvm::IgvmInitializationHeader;
use igvm::IgvmPlatformHeader;
use igvm::IgvmRevision;
use igvm::IgvmSerializer;
use igvm::snp_defs::SevFeatures;
use igvm::snp_defs::SevSelector;
use igvm::snp_defs::SevVmsa;
use igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM;
use igvm_defs::IgvmPageDataFlags;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
use igvm_defs::SnpPolicy;
use igvmfilegen_config::LinuxImage;
use igvmfilegen_config::ResourceType;
use igvmfilegen_config::Resources;
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
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Seek;
use std::mem::discriminant;
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::TopologyBuilder;
use zerocopy::FromZeros;

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
    pub processor_count: u32,
    pub memory_page_count: u64,
    pub c_bit_position: u8,
    pub policy: SnpPolicy,
    pub resources: &'a Resources,
}

pub struct BuildOutput {
    pub guest: IgvmFile,
    pub map: String,
}

#[derive(Debug, Clone)]
struct ImportedPage {
    acceptance: BootPageAcceptance,
    data: Vec<u8>,
    tag: &'static str,
}

#[derive(Debug)]
struct TestIgvmImporter {
    pages: BTreeMap<u64, ImportedPage>,
    registers: Vec<X86Register>,
    ram_page_count: u64,
    c_bit_mask: u64,
}

impl TestIgvmImporter {
    fn new(ram_page_count: u64, c_bit_position: u8) -> Self {
        Self {
            pages: BTreeMap::new(),
            registers: Vec::new(),
            ram_page_count,
            c_bit_mask: 1u64 << c_bit_position,
        }
    }

    fn finish(
        self,
        processor_count: u32,
    ) -> anyhow::Result<(Vec<IgvmDirectiveHeader>, SevVmsa, String)> {
        let vmsa = build_vmsa(&self.registers, self.c_bit_mask)?;
        let (mut directives, map) = build_complete_ram_directives(
            &self.pages,
            &vmsa,
            processor_count,
            self.ram_page_count,
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
        _page_base: u64,
        _page_count: u32,
        _debug_tag: &str,
    ) -> anyhow::Result<ParameterAreaIndex> {
        bail!("IGVM parameter areas are not supported by this fixed image")
    }

    fn create_parameter_area_with_data(
        &mut self,
        _page_base: u64,
        _page_count: u32,
        _debug_tag: &str,
        _initial_data: &[u8],
    ) -> anyhow::Result<ParameterAreaIndex> {
        bail!("IGVM parameter areas are not supported by this fixed image")
    }

    fn import_parameter(
        &mut self,
        _parameter_area: ParameterAreaIndex,
        _byte_offset: u32,
        _parameter_type: IgvmParameterType,
    ) -> anyhow::Result<()> {
        bail!("IGVM parameters are not supported by this fixed image")
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

    fn set_vp_context_page(&mut self, _page_base: u64) -> anyhow::Result<()> {
        bail!("the direct-Linux path must not select a guest-RAM VMSA page")
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
        processor_count,
        memory_page_count,
        c_bit_position,
        policy,
        resources,
    } = params;
    let memory_size = memory_page_count
        .checked_mul(PAGE_SIZE)
        .context("RAM size overflow")?;
    let memory_layout =
        MemoryLayout::new(memory_size, &[], &[], &[], None).context("building memory layout")?;
    let processor_topology = TopologyBuilder::new_x86()
        .build(processor_count)
        .context("building processor topology")?;
    let pcie_host_bridges = Vec::new();
    let acpi_builder = vmm_core::acpi_builder::AcpiTablesBuilder {
        processor_topology: &processor_topology,
        mem_layout: &memory_layout,
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

    let mut importer = TestIgvmImporter::new(memory_page_count, c_bit_position);
    loader::linux::load_x86(
        &mut importer,
        &mut kernel,
        initrd_config,
        &linux.command_line,
        &memory_layout,
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
        }),
    )
    .context("loading direct-Linux image")?;

    let (directives, _vmsa, map) = importer.finish(processor_count)?;
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

    let igvm = IgvmFile::new(
        IgvmRevision::V1,
        platform_headers,
        initialization_headers,
        directives,
    )
    .context("constructing IGVM")?;
    let serializer = IgvmSerializer::new(&igvm).context("measuring SNP IGVM")?;
    let launch_digest: [u8; 48] = serializer
        .measurement_for(IgvmPlatformType::SEV_SNP)
        .context("missing SNP launch measurement")?
        .digest
        .as_slice()
        .try_into()
        .context("SNP launch digest is not 48 bytes")?;
    let mut binary = Vec::new();
    serializer
        .serialize(&mut binary)
        .context("serializing IGVM")?;
    let reparsed = IgvmFile::new_from_binary(&binary, Some(igvm::IsolationType::Snp))
        .context("validating serialized SNP IGVM")?;
    validate_generated_igvm(
        &reparsed,
        launch_digest,
        policy,
        processor_count,
        memory_page_count,
        1u64 << c_bit_position,
    )?;

    Ok(BuildOutput { guest: igvm, map })
}

fn validate_generated_igvm(
    igvm: &IgvmFile,
    expected_launch_digest: [u8; 48],
    expected_policy: u64,
    processor_count: u32,
    ram_page_count: u64,
    c_bit_mask: u64,
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
    let mut secrets_count = 0;
    let mut cpuid_count = 0;
    let mut saw_vmsa = false;

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
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                vp_index,
                vmsa,
                ..
            } => {
                ensure!(*gpa == KVM_VMSA_GPA, "VMSA is not at KVM's fixed GPA");
                ensure!(
                    u32::from(*vp_index) == next_vmsa_index,
                    "VMSA VP contexts are not ordered by VP index"
                );
                ensure!(vmsa.sev_features.snp(), "VMSA does not enable SNP");
                ensure!(!vmsa.sev_features.vtom(), "VMSA unexpectedly enables vTOM");
                ensure!(vmsa.virtual_tom == 0, "VMSA virtual TOM is not zero");
                ensure!(
                    vmsa.cr3 & c_bit_mask != 0,
                    "VMSA CR3 does not contain the configured C-bit"
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
            unexpected => bail!("unexpected directive in fixed SNP IGVM: {unexpected:?}"),
        }
    }

    ensure!(
        covered_pages.len() == ram_page_count as usize
            && covered_pages.first() == Some(&0)
            && covered_pages.last() == Some(&(ram_page_count - 1)),
        "IGVM does not cover every page of the fixed RAM layout"
    );
    ensure!(required_memory_count == 1, "expected one RequiredMemory");
    ensure!(
        next_vmsa_index == processor_count,
        "expected one SNP VMSA per processor"
    );
    ensure!(secrets_count == 1, "expected one SNP secrets page");
    ensure!(cpuid_count == 1, "expected one SNP CPUID page");

    let serializer = IgvmSerializer::new(igvm).context("remeasuring serialized SNP IGVM")?;
    let measured_digest: [u8; 48] = serializer
        .measurement_for(IgvmPlatformType::SEV_SNP)
        .context("serialized IGVM has no SNP measurement")?
        .digest
        .as_slice()
        .try_into()
        .context("serialized SNP launch digest is not 48 bytes")?;
    ensure!(
        measured_digest == expected_launch_digest,
        "serialized IGVM launch digest changed"
    );
    Ok(())
}

fn build_vmsa(registers: &[X86Register], c_bit_mask: u64) -> anyhow::Result<SevVmsa> {
    let mut vmsa = SevVmsa::new_zeroed();
    vmsa.efer = x86defs::X64_EFER_SVME;
    vmsa.sev_features = SevFeatures::new().with_snp(true);
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

fn build_complete_ram_directives(
    imported: &BTreeMap<u64, ImportedPage>,
    vmsa: &SevVmsa,
    processor_count: u32,
    ram_page_count: u64,
) -> anyhow::Result<(Vec<IgvmDirectiveHeader>, String)> {
    let mut directives = Vec::with_capacity(ram_page_count as usize + processor_count as usize);
    let mut map_entries = Vec::new();

    for page in 0..ram_page_count {
        let (directive, tag, kind) = match imported.get(&page) {
            Some(imported) => {
                let (data_type, flags, kind) = page_data_shape(imported.acceptance)?;
                (
                    IgvmDirectiveHeader::PageData {
                        gpa: page * PAGE_SIZE,
                        compatibility_mask: COMPATIBILITY_MASK,
                        flags,
                        data_type,
                        data: imported.data.clone(),
                    },
                    imported.tag.to_owned(),
                    kind,
                )
            }
            None => (
                IgvmDirectiveHeader::PageData {
                    gpa: page * PAGE_SIZE,
                    compatibility_mask: COMPATIBILITY_MASK,
                    flags: IgvmPageDataFlags::new(),
                    data_type: IgvmPageDataType::NORMAL,
                    data: Vec::new(),
                },
                "accepted-zero-ram".to_owned(),
                "NORMAL",
            ),
        };
        directives.push(directive);
        map_entries.push((page, tag, kind));
    }
    for vp_index in 0..processor_count {
        directives.push(IgvmDirectiveHeader::SnpVpContext {
            gpa: KVM_VMSA_GPA,
            compatibility_mask: COMPATIBILITY_MASK,
            vp_index: vp_index
                .try_into()
                .context("VP index does not fit in IGVM")?,
            vmsa: Box::new(*vmsa),
        });
        map_entries.push((
            KVM_VMSA_GPA / PAGE_SIZE,
            format!("snp-vmsa-vp{vp_index}"),
            "VMSA",
        ));
    }

    ensure!(
        imported.keys().all(|page| *page < ram_page_count),
        "an imported page lies outside RAM"
    );
    Ok((directives, format_map(&map_entries, ram_page_count)))
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

fn format_map(entries: &[(u64, String, &'static str)], ram_page_count: u64) -> String {
    let ram_size = ram_page_count * PAGE_SIZE;
    let mut output = format!(
        "IGVM file isolation: SNP (C-bit model)\n\
         Required memory: 0000000000000000 - {ram_size:016x} ({ram_size:#x} bytes)\n\
         IGVM file layout:\n"
    );
    let mut index = 0;
    while index < entries.len() {
        let (start_page, tag, kind) = &entries[index];
        let mut end = index + 1;
        while end < entries.len() && entries[end].1 == *tag && entries[end].2 == *kind {
            end += 1;
        }
        let end_page = entries[end - 1].0 + 1;
        let _ = writeln!(
            output,
            "  {:016x} - {:016x} ({:#x} bytes) {} [{}]",
            start_page * PAGE_SIZE,
            end_page * PAGE_SIZE,
            (end_page - start_page) * PAGE_SIZE,
            tag,
            kind
        );
        index = end;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    const TEST_C_BIT_MASK: u64 = 1 << 51;

    #[test]
    fn vmsa_uses_c_bit_model() {
        let registers = [
            X86Register::Rip(0x100000),
            X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            X86Register::Cr0(x86defs::X64_CR0_PE | x86defs::X64_CR0_PG),
            X86Register::Cr4(x86defs::X64_CR4_PAE),
            X86Register::Efer(x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA),
        ];
        let vmsa = build_vmsa(&registers, TEST_C_BIT_MASK).unwrap();
        assert_eq!(vmsa.rip, 0x100000);
        assert_ne!(vmsa.cr3 & TEST_C_BIT_MASK, 0);
        assert_ne!(vmsa.cr0 & x86defs::X64_CR0_ET, 0);
        assert_ne!(vmsa.cr4 & x86defs::X64_CR4_MCE, 0);
        assert!(vmsa.sev_features.snp());
        assert!(!vmsa.sev_features.vtom());
        assert!(!vmsa.sev_features.debug_swap());
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
    fn complete_ram_has_one_directive_per_page() {
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
        )
        .unwrap();
        let (directives, _) = build_complete_ram_directives(&imported, &vmsa, 1, 4).unwrap();
        assert_eq!(directives.len(), 5);
        assert!(matches!(
            directives[0],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::NORMAL,
                ref data,
                ..
            } if data.is_empty()
        ));
        assert!(matches!(
            directives[1],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::SECRETS,
                ..
            }
        ));
        assert!(matches!(
            directives[2],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::NORMAL,
                ..
            }
        ));
        assert!(matches!(
            directives[4],
            IgvmDirectiveHeader::SnpVpContext {
                gpa: KVM_VMSA_GPA,
                ..
            }
        ));
    }

    #[test]
    fn complete_ram_emits_one_vmsa_per_processor() {
        let vmsa = build_vmsa(
            &[
                X86Register::Rip(0x100000),
                X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            ],
            TEST_C_BIT_MASK,
        )
        .unwrap();
        let (directives, _) = build_complete_ram_directives(&BTreeMap::new(), &vmsa, 4, 1).unwrap();
        let vp_indexes = directives
            .iter()
            .filter_map(|directive| match directive {
                IgvmDirectiveHeader::SnpVpContext { vp_index, .. } => Some(*vp_index),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(vp_indexes, [0, 1, 2, 3]);
    }
}
