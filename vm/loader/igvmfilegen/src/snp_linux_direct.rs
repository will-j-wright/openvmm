// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generation strategy for a self-contained SNP Linux-direct IGVM.

use crate::file_loader::IgvmLoader;
use crate::file_loader::IgvmOutput;
use crate::file_loader::SnpLinuxDirectConfig;
use crate::vp_context_builder::snp::InjectionType;
use anyhow::Context;
use anyhow::ensure;
use chipset_resources::pm::DEFAULT_ACPI_IRQ;
use chipset_resources::pm::DEFAULT_PM_PIO_BASE;
use igvm_defs::SnpPolicy;
use igvmfilegen_config::LinuxImage;
use igvmfilegen_config::ResourceType;
use igvmfilegen_config::Resources;
use loader::importer::BootPageAcceptance;
use loader::importer::ImageLoad;
use loader::importer::X86Register;
use loader::linux::InitrdAddressType;
use loader::linux::InitrdConfig;
use loader_defs::linux::SNP_BOOT_SHIM_MAX_RANGES;
use loader_defs::linux::SNP_BOOT_SHIM_PARAMS_MAGIC;
use loader_defs::linux::SNP_BOOT_SHIM_PARAMS_VERSION;
use loader_defs::linux::SnpBootShimParams;
use loader_defs::linux::SnpBootShimRange;
use serial_16550_resources::ComPort;
use std::fmt::Write as _;
use std::io::Seek;
use vm_topology::memory::MemoryLayout;
use vm_topology::pcie::PcieHostBridge;
use vm_topology::processor::ProcessorTopology;
use vm_topology::processor::TopologyBuilder;
use vm_topology::processor::x86::X86Topology;
use vmm_core::acpi_builder::AcpiArchConfig;
use vmm_core::acpi_builder::AcpiTablesBuilder;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

const PAGE_SIZE: u64 = igvm_defs::PAGE_SIZE_4K;
/// KVM hardcodes the initial VMSA at this GPA and measures it during launch
/// finish, after all userspace-provided launch-update pages.
///
/// Keep the BSP context at this address until KVM supports userspace-supplied
/// VMSA pages. MSHV can import the same context at this fixed address.
const KVM_VMSA_GPA: u64 = 0xffff_ffff_f000;

/// Inputs for the deterministic SNP Linux-direct guest layout.
pub struct BuildParams<'a> {
    /// The Linux payload configuration.
    pub linux: &'a LinuxImage,
    /// The processor count described by the embedded topology and ACPI tables.
    pub processor_count: u32,
    /// The number of measured 4-KiB RAM pages.
    pub memory_page_count: u64,
    /// The page-table address bit used as the SNP encryption bit.
    pub c_bit_position: u8,
    /// The SNP guest policy.
    pub policy: SnpPolicy,
    /// The kernel, optional initrd, and bootshim resources.
    pub resources: &'a Resources,
}

/// The fixed platform layout embedded in the bring-up IGVM.
struct FixedGuestLayout {
    memory: MemoryLayout,
    processors: ProcessorTopology<X86Topology>,
    pcie_host_bridges: Vec<PcieHostBridge>,
}

impl FixedGuestLayout {
    fn new(memory_page_count: u64, processor_count: u32) -> anyhow::Result<Self> {
        let memory_size = memory_page_count
            .checked_mul(PAGE_SIZE)
            .context("RAM size overflow")?;
        let memory = MemoryLayout::new(memory_size, &[], &[], &[], None)
            .context("building memory layout")?;
        let processors = TopologyBuilder::new_x86()
            .build(processor_count)
            .context("building processor topology")?;

        Ok(Self {
            memory,
            processors,
            pcie_host_bridges: Vec::new(),
        })
    }

    fn acpi_builder(&self) -> AcpiTablesBuilder<'_, X86Topology> {
        // This profile embeds OpenVMM's standard PC-compatible chipset
        // contract. The ACPI values must match the devices supplied by the
        // backend.
        //
        // TODO: Accept an external platform description when this bring-up
        // profile needs layouts other than the fixed OpenVMM defaults.
        AcpiTablesBuilder {
            processor_topology: &self.processors,
            mem_layout: &self.memory,
            cache_topology: None,
            pcie_host_bridges: &self.pcie_host_bridges,
            slit_info: None,
            generic_initiators: &[],
            arch: AcpiArchConfig::X86 {
                with_ioapic: true,
                with_pic: true,
                with_pit: true,
                with_psp: false,
                pm_base: DEFAULT_PM_PIO_BASE,
                acpi_irq: DEFAULT_ACPI_IRQ,
                iommu: None,
            },
        }
    }
}

fn open_linux_resources(
    linux: &LinuxImage,
    resources: &Resources,
) -> anyhow::Result<(fs_err::File, Option<fs_err::File>)> {
    let kernel_path = resources
        .get(ResourceType::LinuxKernel)
        .context("Linux kernel resource is missing")?;
    let kernel = fs_err::File::open(kernel_path)
        .with_context(|| format!("opening kernel {}", kernel_path.display()))?;

    let initrd = if linux.use_initrd {
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

    Ok((kernel, initrd))
}

fn initrd_config(initrd: &mut Option<fs_err::File>) -> anyhow::Result<Option<InitrdConfig<'_>>> {
    let Some(initrd) = initrd else {
        return Ok(None);
    };
    let size = initrd
        .seek(std::io::SeekFrom::End(0))
        .context("measuring initrd")?;
    initrd.rewind().context("rewinding initrd")?;
    Ok(Some(InitrdConfig {
        initrd_address: InitrdAddressType::AfterKernel,
        initrd,
        size,
    }))
}

fn new_loader(
    policy: SnpPolicy,
    c_bit_position: u8,
    memory_page_count: u64,
) -> IgvmLoader<X86Register> {
    IgvmLoader::new_snp_linux_direct(SnpLinuxDirectConfig {
        policy,
        c_bit_mask: 1u64 << c_bit_position,
        ram_page_count: memory_page_count,
        vmsa_page: Some(KVM_VMSA_GPA / PAGE_SIZE),
        injection_type: InjectionType::Normal,
    })
}

/// Builds the deterministic topology, ACPI tables, Linux payload, and BSP
/// launch context embedded in the standalone SNP IGVM.
pub fn build(params: BuildParams<'_>) -> anyhow::Result<IgvmOutput> {
    let BuildParams {
        linux,
        processor_count,
        memory_page_count,
        c_bit_position,
        policy,
        resources,
    } = params;

    let layout = FixedGuestLayout::new(memory_page_count, processor_count)?;
    let acpi_builder = layout.acpi_builder();
    let (mut kernel, mut initrd) = open_linux_resources(linux, resources)?;
    let initrd_config = initrd_config(&mut initrd)?;
    let mut loader = new_loader(policy, c_bit_position, memory_page_count);
    let com1 = ComPort::Com1;

    let load_info = loader::linux::load_x86(
        &mut loader.loader(),
        &mut kernel,
        initrd_config,
        &linux.command_line,
        &layout.memory,
        |gpa| {
            let tables = acpi_builder.build_acpi_tables(gpa, |dsdt| {
                dsdt.add_apic();
                dsdt.add_uart(b"\\_SB.UAR1", b"COM1", 1, com1.io_port(), com1.irq().into());
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

    let linux_entry = load_info.kernel.entrypoint;
    let linux_zero_page = loader::linux::ZERO_PAGE_BASE;
    let kernel_runtime_end = kernel_runtime_end(
        load_info.kernel.gpa,
        load_info.kernel.size,
        load_info
            .bzimage_setup_header
            .as_ref()
            .map(|header| (header.pref_address, u64::from(header.init_size))),
    )?;
    let shim_base = align_up_to_page(loader.next_available_gpa()?.max(kernel_runtime_end))?;
    let bootshim_path = resources
        .get(ResourceType::SnpBootshim)
        .context("SNP bootshim resource is missing")?;
    let mut bootshim = fs_err::File::open(bootshim_path)
        .with_context(|| format!("opening SNP bootshim {}", bootshim_path.display()))?;
    let shim_load_info = loader::elf::load_static_elf(
        &mut loader.loader(),
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
    let bootshim_ranges = loader
        .unimported_ram_ranges([params_page])?
        .into_iter()
        .map(|range| SnpBootShimRange {
            start_gpn: range.start,
            page_count: range.end - range.start,
        })
        .collect::<Vec<_>>();
    let bootshim_params = build_bootshim_params(
        linux_entry,
        linux_zero_page,
        memory_page_count * PAGE_SIZE,
        &bootshim_ranges,
    )?;
    {
        let mut importer = loader.loader();
        importer
            .import_pages(
                params_page,
                1,
                "snp-bootshim-params",
                BootPageAcceptance::Exclusive,
                bootshim_params.as_bytes(),
            )
            .context("importing SNP bootshim parameters")?;
        importer.import_vp_register(X86Register::Rip(shim_load_info.entrypoint))?;
        importer.import_vp_register(X86Register::Rsi(params_gpa))?;
    }

    let mut output = loader.finalize().context("finalizing SNP IGVM")?;
    append_bootshim_ranges_to_map(&mut output.map, &bootshim_ranges);
    Ok(output)
}

fn align_up_to_page(value: u64) -> anyhow::Result<u64> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
        .context("page alignment overflow")
}

fn kernel_runtime_end(
    load_gpa: u64,
    image_size: u64,
    bzimage_runtime: Option<(u64, u64)>,
) -> anyhow::Result<u64> {
    let (runtime_gpa, runtime_size) = bzimage_runtime
        .map(|(preferred_gpa, init_size)| (load_gpa.max(preferred_gpa), init_size))
        .unwrap_or((load_gpa, image_size));
    runtime_gpa
        .checked_add(runtime_size)
        .context("Linux runtime image end overflow")
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

fn append_bootshim_ranges_to_map(output: &mut String, ranges: &[SnpBootShimRange]) {
    let page_count = ranges.iter().map(|range| range.page_count).sum::<u64>();
    let _ = writeln!(
        output,
        "Bootshim-accepted RAM: {page_count:#x} pages ({:#x} bytes)",
        page_count * PAGE_SIZE
    );
    for range in ranges {
        let end = range.start_gpn + range.page_count;
        let _ = writeln!(
            output,
            "  {:016x} - {:016x} ({:#x} bytes) snp-bootshim-accepted-ram [PVALIDATE]",
            range.start_gpn * PAGE_SIZE,
            end * PAGE_SIZE,
            range.page_count * PAGE_SIZE
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vp_context_builder::VpContextBuilder;
    use igvm::IgvmDirectiveHeader;
    use igvm_defs::IgvmPageDataType;
    use loader::importer::ImageLoad;
    use test_with_tracing::test;
    use zerocopy::FromBytes;

    const TEST_POLICY: u64 = 0x30000;
    const TEST_C_BIT_MASK: u64 = 1 << 51;
    const TEST_SHIM_ENTRY: u64 = 0x100000;

    fn test_loader(ram_page_count: u64) -> IgvmLoader<X86Register> {
        IgvmLoader::new_snp_linux_direct(SnpLinuxDirectConfig {
            policy: SnpPolicy::from(TEST_POLICY),
            c_bit_mask: TEST_C_BIT_MASK,
            ram_page_count,
            vmsa_page: Some(KVM_VMSA_GPA / PAGE_SIZE),
            injection_type: InjectionType::Normal,
        })
    }

    fn import_test_registers(importer: &mut dyn ImageLoad<X86Register>, params_gpa: u64) {
        for register in [
            X86Register::Rip(TEST_SHIM_ENTRY),
            X86Register::Rsi(params_gpa),
            X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            X86Register::Cr0(x86defs::X64_CR0_PE | x86defs::X64_CR0_PG),
            X86Register::Cr4(x86defs::X64_CR4_PAE),
            X86Register::Efer(x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA),
        ] {
            importer.import_vp_register(register).unwrap();
        }
    }

    #[test]
    fn fixed_layout_supports_one_and_many_processors() {
        for processor_count in [1, 4] {
            let layout = FixedGuestLayout::new(64, processor_count).unwrap();
            assert_eq!(layout.processors.vp_count(), processor_count);
            assert_eq!(layout.memory.ram().len(), 1);
        }
    }

    #[test]
    fn bzimage_runtime_uses_preferred_address_above_load_address() {
        assert_eq!(
            kernel_runtime_end(0x100000, 0x200000, Some((0x400000, 0x300000))).unwrap(),
            0x700000
        );
    }

    #[test]
    fn bzimage_runtime_uses_load_address_above_preferred_address() {
        assert_eq!(
            kernel_runtime_end(0x400000, 0x200000, Some((0x100000, 0x300000))).unwrap(),
            0x700000
        );
    }

    #[test]
    fn raw_kernel_runtime_uses_image_size() {
        assert_eq!(
            kernel_runtime_end(0x100000, 0x200000, None).unwrap(),
            0x300000
        );
    }

    #[test]
    fn rejects_kernel_runtime_end_overflow() {
        assert!(kernel_runtime_end(u64::MAX, 1, None).is_err());
        assert!(kernel_runtime_end(0, 0, Some((u64::MAX, 1))).is_err());
    }

    #[test]
    fn vmsa_uses_the_bootshim_handoff() {
        let params_gpa = 0x6000;
        let mut context = crate::vp_context_builder::snp::SnpHardwareContext::new_linux_direct(
            TEST_C_BIT_MASK,
            InjectionType::Normal,
        );
        for register in [
            X86Register::Rip(TEST_SHIM_ENTRY),
            X86Register::Rsi(params_gpa),
            X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
        ] {
            context.import_vp_register(register);
        }

        let vmsa = context.vmsa();
        assert_eq!(vmsa.rip, TEST_SHIM_ENTRY);
        assert_eq!(vmsa.rsi, params_gpa);
        assert_ne!(vmsa.cr3 & TEST_C_BIT_MASK, 0);
    }

    #[test]
    fn sparse_loader_covers_unimported_ram_and_hands_off_to_bootshim() {
        const RAM_PAGE_COUNT: u64 = 8;
        const PARAMS_PAGE: u64 = 6;
        let params_gpa = PARAMS_PAGE * PAGE_SIZE;
        let mut loader = test_loader(RAM_PAGE_COUNT);
        {
            let mut importer = loader.loader();
            importer
                .import_pages(1, 1, "secrets", BootPageAcceptance::SecretsPage, &[])
                .unwrap();
            importer
                .import_pages(2, 1, "cpuid", BootPageAcceptance::CpuidPage, &[])
                .unwrap();
        }

        let ranges = loader.unimported_ram_ranges([PARAMS_PAGE]).unwrap();
        assert_eq!(ranges, [0..1, 3..6, 7..8]);
        let ranges = ranges
            .iter()
            .map(|range| SnpBootShimRange {
                start_gpn: range.start,
                page_count: range.end - range.start,
            })
            .collect::<Vec<_>>();
        let params = build_bootshim_params(
            0x200000,
            loader::linux::ZERO_PAGE_BASE,
            RAM_PAGE_COUNT * PAGE_SIZE,
            &ranges,
        )
        .unwrap();
        {
            let mut importer = loader.loader();
            importer
                .import_pages(
                    PARAMS_PAGE,
                    1,
                    "snp-bootshim-params",
                    BootPageAcceptance::Exclusive,
                    params.as_bytes(),
                )
                .unwrap();
            import_test_registers(&mut importer, params_gpa);
        }

        let output = loader.finalize().unwrap();
        let mut imported_pages = Vec::new();
        let mut required_memory = None;
        let mut handoff = None;
        let mut serialized_params = None;
        for directive in output.guest.directives() {
            match directive {
                IgvmDirectiveHeader::PageData {
                    gpa,
                    data_type,
                    data,
                    ..
                } => {
                    imported_pages.push(*gpa / PAGE_SIZE);
                    if *gpa == params_gpa {
                        assert_eq!(*data_type, IgvmPageDataType::NORMAL);
                        let mut page = [0; PAGE_SIZE as usize];
                        page[..data.len()].copy_from_slice(data);
                        serialized_params =
                            Some(SnpBootShimParams::read_from_bytes(&page).unwrap());
                    }
                }
                IgvmDirectiveHeader::RequiredMemory {
                    gpa,
                    number_of_bytes,
                    ..
                } => required_memory = Some((*gpa, *number_of_bytes)),
                IgvmDirectiveHeader::SnpVpContext { vmsa, .. } => {
                    handoff = Some((vmsa.rip, vmsa.rsi));
                }
                _ => {}
            }
        }

        imported_pages.sort_unstable();
        assert_eq!(imported_pages, [1, 2, PARAMS_PAGE]);
        assert_eq!(
            required_memory,
            Some((0, (RAM_PAGE_COUNT * PAGE_SIZE) as u32))
        );
        assert_eq!(handoff, Some((TEST_SHIM_ENTRY, params_gpa)));
        assert_eq!(serialized_params, Some(params));
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
    fn rejects_unaligned_bootshim_placement() {
        assert!(align_up_to_page(u64::MAX).is_err());
    }
}
