// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generation library for the standalone SNP test IGVM executable.

#![forbid(unsafe_code)]

mod id_block;

use anyhow::Context;
use anyhow::bail;
use anyhow::ensure;
use crypto::sha_384::Sha384;
use igvm::IgvmDirectiveHeader;
use igvm::IgvmFile;
use igvm::IgvmInitializationHeader;
use igvm::IgvmPlatformHeader;
use igvm::IgvmRevision;
use igvm::snp_defs::SevFeatures;
use igvm::snp_defs::SevSelector;
use igvm::snp_defs::SevVmsa;
use igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM;
use igvm_defs::IgvmPageDataFlags;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
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
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fmt::Write as _;
use std::io::Seek;
use std::io::Write;
use std::mem::discriminant;
use std::path::Path;
use std::path::PathBuf;
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::TopologyBuilder;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

const COMPATIBILITY_MASK: u32 = 1;
const PAGE_SIZE: u64 = igvm_defs::PAGE_SIZE_4K;
const RAM_MIB: u64 = 160;
const RAM_SIZE: u64 = RAM_MIB * 1024 * 1024;
const RAM_PAGE_COUNT: u64 = RAM_SIZE / PAGE_SIZE;
const PROCESSOR_COUNT: u32 = 1;
const GUEST_SVN: u32 = 1;
/// Test-only host assumption. Real SNP software must read this from CPUID
/// 0x8000_001f rather than assuming that the encryption bit is always 51.
const SNP_C_BIT_POSITION: u8 = 51;
const SNP_C_BIT_MASK: u64 = 1 << SNP_C_BIT_POSITION;
/// KVM hardcodes the initial VMSA at this GPA and measures it during launch
/// finish, after all userspace-provided launch-update pages.
const KVM_VMSA_GPA: u64 = 0xffff_ffff_f000;
const SNP_POLICY: u64 = (1 << 19) | (1 << 17) | (1 << 16);
const KERNEL_COMMAND_LINE: &str = "console=ttyS0 earlyprintk=serial earlycon panic=-1";
const PM_BASE: u16 = 0x400;
const ACPI_IRQ: u32 = 9;
const COM1_BASE: u16 = 0x3f8;
const COM1_IRQ: u32 = 4;
const MEASUREMENT_CLASS_ID: &str = "7fb00ee4-a7ff-11ed-9e2f-00155d09de56";

/// Inputs accepted by the fixed-shape generator.
#[derive(Debug, Clone)]
pub struct GenerateOptions {
    /// Linux kernel image.
    pub kernel: PathBuf,
    /// Optional initrd image.
    pub initrd: Option<PathBuf>,
    /// Output IGVM path.
    pub output: PathBuf,
}

/// Paths written by [`generate`].
#[derive(Debug, Clone)]
pub struct GeneratedArtifacts {
    /// Serialized IGVM.
    pub igvm: PathBuf,
    /// Human-readable GPA map.
    pub map: PathBuf,
    /// SNP launch measurement document.
    pub measurement: PathBuf,
    /// Expected OpenVMM launch configuration.
    pub openvmm_contract: PathBuf,
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
}

impl TestIgvmImporter {
    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            registers: Vec::new(),
        }
    }

    fn finish(self) -> anyhow::Result<(Vec<IgvmDirectiveHeader>, SevVmsa, String)> {
        let vmsa = build_vmsa(&self.registers)?;
        let (mut directives, map) =
            build_complete_ram_directives(&self.pages, &vmsa, RAM_PAGE_COUNT)?;
        directives.insert(
            0,
            IgvmDirectiveHeader::RequiredMemory {
                gpa: 0,
                compatibility_mask: COMPATIBILITY_MASK,
                number_of_bytes: RAM_SIZE
                    .try_into()
                    .expect("fixed RAM size fits in an IGVM required-memory directive"),
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
            page_end <= RAM_PAGE_COUNT,
            "{debug_tag} lies outside the fixed {RAM_MIB} MiB RAM layout"
        );

        let mut data = data.to_vec();
        if debug_tag == "linux-pagetables" {
            patch_confidential_page_tables(&mut data)?;
        }

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
            page_end <= RAM_PAGE_COUNT,
            "required memory lies outside the fixed RAM layout"
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

/// Generate the fixed SNP test IGVM and companion artifacts.
pub fn generate(options: GenerateOptions) -> anyhow::Result<GeneratedArtifacts> {
    let memory_layout =
        MemoryLayout::new(RAM_SIZE, &[], &[], &[], None).context("building memory layout")?;
    let processor_topology = TopologyBuilder::new_x86()
        .build(PROCESSOR_COUNT)
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

    let mut kernel = fs_err::File::open(&options.kernel)
        .with_context(|| format!("opening kernel {}", options.kernel.display()))?;
    let mut initrd = match &options.initrd {
        Some(path) => Some(
            fs_err::File::open(path)
                .with_context(|| format!("opening initrd {}", path.display()))?,
        ),
        None => None,
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

    let command_line =
        CString::new(KERNEL_COMMAND_LINE).expect("fixed kernel command line has no NUL");
    let mut importer = TestIgvmImporter::new();
    loader::linux::load_x86(
        &mut importer,
        &mut kernel,
        initrd_config,
        &command_line,
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
        Some(loader::linux::SnpBootConfig),
    )
    .context("loading direct-Linux image")?;

    let (mut directives, _vmsa, map) = importer.finish()?;
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
        policy: SNP_POLICY,
        compatibility_mask: COMPATIBILITY_MASK,
    }];

    let launch_digest = generate_snp_measurement(&initialization_headers, &directives)
        .context("computing SNP launch digest")?;
    directives.push(id_block::signed_id_block(
        launch_digest,
        GUEST_SVN,
        SNP_POLICY,
    )?);

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
    validate_generated_igvm(&reparsed, launch_digest)?;

    write_artifacts(&options, &binary, &map, launch_digest)
}

fn validate_generated_igvm(
    igvm: &IgvmFile,
    expected_launch_digest: [u8; 48],
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
            } if *policy == SNP_POLICY
        )),
        "serialized file lost its SNP guest policy"
    );

    let mut covered_pages = BTreeSet::new();
    let mut required_memory_count = 0;
    let mut vmsa_count = 0;
    let mut id_block_count = 0;
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
                ensure!(page < RAM_PAGE_COUNT, "PageData lies outside RAM");
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
            IgvmDirectiveHeader::SnpVpContext { gpa, vmsa, .. } => {
                ensure!(!saw_vmsa, "multiple or reordered VMSA directives");
                ensure!(*gpa == KVM_VMSA_GPA, "VMSA is not at KVM's fixed GPA");
                ensure!(vmsa.sev_features.snp(), "VMSA does not enable SNP");
                ensure!(!vmsa.sev_features.vtom(), "VMSA unexpectedly enables vTOM");
                ensure!(vmsa.virtual_tom == 0, "VMSA virtual TOM is not zero");
                ensure!(
                    vmsa.cr3 & SNP_C_BIT_MASK != 0,
                    "VMSA CR3 does not contain C-bit 51"
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
                vmsa_count += 1;
                saw_vmsa = true;
            }
            IgvmDirectiveHeader::RequiredMemory {
                gpa,
                number_of_bytes,
                vtl2_protectable,
                ..
            } => {
                ensure!(
                    *gpa == 0 && u64::from(*number_of_bytes) == RAM_SIZE && !vtl2_protectable,
                    "unexpected RequiredMemory directive"
                );
                required_memory_count += 1;
            }
            IgvmDirectiveHeader::SnpIdBlock { ld, guest_svn, .. } => {
                ensure!(
                    *ld == expected_launch_digest && *guest_svn == GUEST_SVN,
                    "SNP ID block does not match the generated launch digest"
                );
                id_block_count += 1;
            }
            unexpected => bail!("unexpected directive in fixed SNP IGVM: {unexpected:?}"),
        }
    }

    ensure!(
        covered_pages.len() == RAM_PAGE_COUNT as usize
            && covered_pages.first() == Some(&0)
            && covered_pages.last() == Some(&(RAM_PAGE_COUNT - 1)),
        "IGVM does not cover every page of the fixed RAM layout"
    );
    ensure!(required_memory_count == 1, "expected one RequiredMemory");
    ensure!(vmsa_count == 1, "expected one SNP VMSA");
    ensure!(id_block_count == 1, "expected one SNP ID block");
    ensure!(secrets_count == 1, "expected one SNP secrets page");
    ensure!(cpuid_count == 1, "expected one SNP CPUID page");

    let measured_digest = generate_snp_measurement(igvm.initializations(), igvm.directives())
        .context("remeasuring serialized SNP IGVM")?;
    ensure!(
        measured_digest == expected_launch_digest,
        "serialized IGVM launch digest changed"
    );
    Ok(())
}

fn generate_snp_measurement(
    initialization_headers: &[IgvmInitializationHeader],
    directives: &[IgvmDirectiveHeader],
) -> anyhow::Result<[u8; 48]> {
    ensure!(
        initialization_headers.iter().any(|header| matches!(
            header,
            IgvmInitializationHeader::GuestPolicy {
                compatibility_mask,
                ..
            } if compatibility_mask & COMPATIBILITY_MASK == COMPATIBILITY_MASK
        )),
        "SNP guest policy is missing"
    );

    let zero_page = [0; PAGE_SIZE as usize];
    let zero_digest = crypto::sha_384::sha_384(&zero_page);
    let mut launch_digest = [0; 48];
    let mut padded_page = vec![0; PAGE_SIZE as usize];

    let mut measure_page = |page_type: x86defs::snp::SnpPageType,
                            gpa: u64,
                            page_data: Option<&[u8]>|
     -> anyhow::Result<()> {
        let contents = match page_data {
            Some([]) => zero_digest,
            Some(data) if data.len() < PAGE_SIZE as usize => {
                padded_page.fill(0);
                padded_page[..data.len()].copy_from_slice(data);
                crypto::sha_384::sha_384(&padded_page)
            }
            Some(data) if data.len() == PAGE_SIZE as usize => crypto::sha_384::sha_384(data),
            Some(data) => bail!("cannot measure {}-byte page data", data.len()),
            None => [0; 48],
        };
        let page_info = x86defs::snp::SnpPageInfo {
            digest_current: launch_digest,
            contents,
            length: size_of::<x86defs::snp::SnpPageInfo>() as u16,
            page_type,
            imi_page_bit: 0,
            lower_vmpl_permissions: 0,
            gpa,
        };
        let mut hash = Sha384::new();
        hash.update(page_info.as_bytes());
        launch_digest = hash.finish();
        Ok(())
    };

    for directive in directives {
        if directive
            .compatibility_mask()
            .map(|mask| mask & COMPATIBILITY_MASK != COMPATIBILITY_MASK)
            .unwrap_or(false)
        {
            continue;
        }
        match directive {
            IgvmDirectiveHeader::PageData {
                gpa,
                flags,
                data_type,
                data,
                ..
            } if !flags.shared() => {
                let (page_type, data) = if *data_type == IgvmPageDataType::SECRETS {
                    (x86defs::snp::SnpPageType::SECRETS, None)
                } else if *data_type == IgvmPageDataType::CPUID_DATA
                    || *data_type == IgvmPageDataType::CPUID_XF
                {
                    (x86defs::snp::SnpPageType::CPUID, None)
                } else if flags.unmeasured() {
                    (x86defs::snp::SnpPageType::UNMEASURED, None)
                } else {
                    (x86defs::snp::SnpPageType::NORMAL, Some(data.as_slice()))
                };
                measure_page(page_type, *gpa, data)?;
            }
            IgvmDirectiveHeader::SnpVpContext { gpa, vmsa, .. } => {
                measure_page(x86defs::snp::SnpPageType::VMSA, *gpa, Some(vmsa.as_bytes()))?;
            }
            IgvmDirectiveHeader::PageData { .. }
            | IgvmDirectiveHeader::RequiredMemory { .. }
            | IgvmDirectiveHeader::SnpIdBlock { .. } => {}
            unexpected => bail!("cannot measure unexpected directive {unexpected:?}"),
        }
    }
    Ok(launch_digest)
}

fn patch_confidential_page_tables(data: &mut [u8]) -> anyhow::Result<()> {
    ensure!(
        data.len().is_multiple_of(size_of::<u64>()),
        "Linux page-table data is not a whole number of entries"
    );
    for entry in data.chunks_exact_mut(size_of::<u64>()) {
        let mut value = u64::from_le_bytes(
            entry
                .try_into()
                .expect("an exact eight-byte chunk converts to an array"),
        );
        if value & 1 != 0 {
            value |= SNP_C_BIT_MASK;
            entry.copy_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

fn build_vmsa(registers: &[X86Register]) -> anyhow::Result<SevVmsa> {
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
            X86Register::Cr3(value) => vmsa.cr3 = value | SNP_C_BIT_MASK,
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
        vmsa.cr3 & SNP_C_BIT_MASK != 0,
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
    ram_page_count: u64,
) -> anyhow::Result<(Vec<IgvmDirectiveHeader>, String)> {
    let mut directives = Vec::with_capacity(ram_page_count as usize + 1);
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
    directives.push(IgvmDirectiveHeader::SnpVpContext {
        gpa: KVM_VMSA_GPA,
        compatibility_mask: COMPATIBILITY_MASK,
        vp_index: 0,
        vmsa: Box::new(*vmsa),
    });
    map_entries.push((KVM_VMSA_GPA / PAGE_SIZE, "snp-vmsa".to_owned(), "VMSA"));

    ensure!(
        imported.keys().all(|page| *page < ram_page_count),
        "an imported page lies outside RAM"
    );
    Ok((directives, format_map(&map_entries)))
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

fn format_map(entries: &[(u64, String, &'static str)]) -> String {
    let mut output = String::from(
        "IGVM file isolation: SNP (C-bit model, fixed bit 51)\n\
         Required memory: 0000000000000000 - 000000000a000000 (0xa000000 bytes)\n\
         IGVM file layout:\n",
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

#[derive(Debug, Serialize)]
struct MeasurementDocument {
    environment: MeasurementEnvironment,
    series: Vec<MeasurementInstance>,
}

#[derive(Debug, Serialize)]
struct MeasurementEnvironment {
    class_id: &'static str,
}

#[derive(Debug, Serialize)]
struct MeasurementInstance {
    reference: MeasurementReference,
    endorsement: MeasurementEndorsement,
}

#[derive(Debug, Serialize)]
struct MeasurementReference {
    snp_ld: String,
}

#[derive(Debug, Serialize)]
struct MeasurementEndorsement {
    snp_isvsvn: u32,
    build_info: MeasurementBuildInfo,
}

#[derive(Debug, Serialize)]
struct MeasurementBuildInfo {
    debug_build: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OpenvmmLaunchContract {
    schema_version: u32,
    hypervisor: &'static str,
    isolation: &'static str,
    memory_mib: u64,
    processor_count: u32,
    serial_console: &'static str,
    vmbus: bool,
    pcie: bool,
    disks: bool,
    expected_snp_c_bit_position: u8,
    kvm_vmsa_gpa: &'static str,
    all_ram_pages_are_measured_normal: bool,
    kvm_zero_page_optimization_allowed: bool,
    kernel_command_line: &'static str,
    suggested_arguments: Vec<String>,
}

fn write_artifacts(
    options: &GenerateOptions,
    binary: &[u8],
    map: &str,
    launch_digest: [u8; 48],
) -> anyhow::Result<GeneratedArtifacts> {
    if let Some(parent) = options.output.parent() {
        fs_err::create_dir_all(parent)
            .with_context(|| format!("creating output directory {}", parent.display()))?;
    }
    fs_err::write(&options.output, binary)
        .with_context(|| format!("writing IGVM {}", options.output.display()))?;

    let map_path = append_to_file_name(&options.output, ".map")?;
    fs_err::write(&map_path, map).with_context(|| format!("writing map {}", map_path.display()))?;

    let measurement_path = replace_file_name(&options.output, "-snp.json")?;
    let measurement = MeasurementDocument {
        environment: MeasurementEnvironment {
            class_id: MEASUREMENT_CLASS_ID,
        },
        series: vec![MeasurementInstance {
            reference: MeasurementReference {
                snp_ld: hex::encode_upper(launch_digest),
            },
            endorsement: MeasurementEndorsement {
                snp_isvsvn: GUEST_SVN,
                build_info: MeasurementBuildInfo { debug_build: true },
            },
        }],
    };
    write_json(&measurement_path, &measurement)?;

    let openvmm_contract_path = replace_file_name(&options.output, ".openvmm.json")?;
    let contract = openvmm_launch_contract(&options.output);
    write_json(&openvmm_contract_path, &contract)?;

    Ok(GeneratedArtifacts {
        igvm: options.output.clone(),
        map: map_path,
        measurement: measurement_path,
        openvmm_contract: openvmm_contract_path,
    })
}

fn openvmm_launch_contract(output: &Path) -> OpenvmmLaunchContract {
    OpenvmmLaunchContract {
        schema_version: 1,
        hypervisor: "kvm",
        isolation: "snp",
        memory_mib: RAM_MIB,
        processor_count: PROCESSOR_COUNT,
        serial_console: "com1",
        vmbus: false,
        pcie: false,
        disks: false,
        expected_snp_c_bit_position: SNP_C_BIT_POSITION,
        kvm_vmsa_gpa: "0xFFFFFFFFF000",
        all_ram_pages_are_measured_normal: true,
        kvm_zero_page_optimization_allowed: false,
        kernel_command_line: KERNEL_COMMAND_LINE,
        suggested_arguments: vec![
            "--hypervisor".into(),
            "kvm".into(),
            "--isolation".into(),
            "snp".into(),
            "--igvm".into(),
            output.display().to_string(),
            "--com1".into(),
            "console".into(),
            "--no-vmbus".into(),
            "-m".into(),
            "160MB".into(),
            "-p".into(),
            "1".into(),
        ],
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let mut file =
        fs_err::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("serializing {}", path.display()))?;
    writeln!(file).with_context(|| format!("finishing {}", path.display()))?;
    Ok(())
}

fn append_to_file_name(path: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let mut file_name = path
        .file_name()
        .context("output path must have a file name")?
        .to_os_string();
    file_name.push(suffix);
    Ok(path.with_file_name(file_name))
}

fn replace_file_name(path: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let mut file_name = path
        .file_stem()
        .context("output path must have a file stem")?
        .to_os_string();
    file_name.push(suffix);
    Ok(path.with_file_name(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn page_table_patch_sets_only_present_entries() {
        let entries = [0u64, 0x2003, 0x4002];
        let mut data = entries.as_bytes().to_vec();
        patch_confidential_page_tables(&mut data).unwrap();
        let patched: Vec<_> = data
            .chunks_exact(8)
            .map(|entry| u64::from_le_bytes(entry.try_into().unwrap()))
            .collect();
        assert_eq!(patched[0], 0);
        assert_eq!(patched[1], 0x2003 | SNP_C_BIT_MASK);
        assert_eq!(patched[2], 0x4002);
    }

    #[test]
    fn vmsa_uses_c_bit_model() {
        let registers = [
            X86Register::Rip(0x100000),
            X86Register::Cr3(0x4000 | SNP_C_BIT_MASK),
            X86Register::Cr0(x86defs::X64_CR0_PE | x86defs::X64_CR0_PG),
            X86Register::Cr4(x86defs::X64_CR4_PAE),
            X86Register::Efer(x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA),
        ];
        let vmsa = build_vmsa(&registers).unwrap();
        assert_eq!(vmsa.rip, 0x100000);
        assert_ne!(vmsa.cr3 & SNP_C_BIT_MASK, 0);
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
        let vmsa = build_vmsa(&[
            X86Register::Rip(0x100000),
            X86Register::Cr3(0x4000 | SNP_C_BIT_MASK),
        ])
        .unwrap();
        let (directives, _) = build_complete_ram_directives(&imported, &vmsa, 4).unwrap();
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
    fn launch_contract_matches_fixed_image() {
        let contract = openvmm_launch_contract(Path::new("/tmp/test.igvm"));
        assert_eq!(contract.memory_mib, 160);
        assert_eq!(contract.processor_count, 1);
        assert_eq!(contract.expected_snp_c_bit_position, 51);
        assert_eq!(contract.kvm_vmsa_gpa, "0xFFFFFFFFF000");
        assert!(contract.all_ram_pages_are_measured_normal);
        assert!(!contract.kvm_zero_page_optimization_allowed);
        assert!(!contract.vmbus);
        assert!(
            contract
                .suggested_arguments
                .windows(2)
                .any(|args| args == ["--igvm", "/tmp/test.igvm"])
        );
    }
}
