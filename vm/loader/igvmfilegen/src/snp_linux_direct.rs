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
use igvm::IgvmSerializer;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
use igvm_defs::SnpPolicy;
use igvmfilegen_config::LinuxImage;
use igvmfilegen_config::ResourceType;
use igvmfilegen_config::Resources;
use loader::importer::X86Register;
use loader::linux::InitrdAddressType;
use loader::linux::InitrdConfig;
use std::collections::BTreeSet;
use std::io::Seek;
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::TopologyBuilder;

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

pub fn build(params: BuildParams<'_>) -> anyhow::Result<crate::file_loader::IgvmOutput> {
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

    let mut loader = crate::file_loader::IgvmLoader::<X86Register>::new_snp_linux_direct(
        crate::file_loader::SnpLinuxDirectConfig {
            policy,
            c_bit_mask: 1u64 << c_bit_position,
            ram_page_count: memory_page_count,
            vp_context_count: processor_count,
            vmsa_page: Some(KVM_VMSA_GPA / PAGE_SIZE),
            injection_type: crate::vp_context_builder::snp::InjectionType::Normal,
            import_all_ram: true,
        },
    );
    loader::linux::load_x86(
        &mut loader.loader(),
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

    let policy: u64 = policy.into();
    let output = loader.finalize().context("finalizing SNP IGVM")?;
    let serializer = IgvmSerializer::new(&output.guest).context("measuring SNP IGVM")?;
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

    Ok(output)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_loader::IgvmLoader;
    use crate::file_loader::SnpLinuxDirectConfig;
    use crate::vp_context_builder::VpContextBuilder;
    use crate::vp_context_builder::snp::InjectionType;
    use crate::vp_context_builder::snp::SnpHardwareContext;
    use loader::importer::BootPageAcceptance;
    use loader::importer::ImageLoad;
    use test_with_tracing::test;

    const TEST_C_BIT_MASK: u64 = 1 << 51;

    fn test_loader(ram_page_count: u64, vp_context_count: u32) -> IgvmLoader<X86Register> {
        IgvmLoader::new_snp_linux_direct(SnpLinuxDirectConfig {
            policy: SnpPolicy::from(0x30000),
            c_bit_mask: TEST_C_BIT_MASK,
            ram_page_count,
            vp_context_count,
            vmsa_page: Some(KVM_VMSA_GPA / PAGE_SIZE),
            injection_type: InjectionType::Normal,
            import_all_ram: true,
        })
    }

    fn import_test_registers(importer: &mut dyn ImageLoad<X86Register>) {
        importer
            .import_vp_register(X86Register::Rip(0x100000))
            .unwrap();
        importer
            .import_vp_register(X86Register::Cr3(0x4000 | TEST_C_BIT_MASK))
            .unwrap();
        importer
            .import_vp_register(X86Register::Cr0(x86defs::X64_CR0_PE | x86defs::X64_CR0_PG))
            .unwrap();
        importer
            .import_vp_register(X86Register::Cr4(x86defs::X64_CR4_PAE))
            .unwrap();
        importer
            .import_vp_register(X86Register::Efer(
                x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA,
            ))
            .unwrap();
    }

    #[test]
    fn vmsa_uses_c_bit_model() {
        let mut context =
            SnpHardwareContext::new_linux_direct(TEST_C_BIT_MASK, InjectionType::Normal);
        for register in [
            X86Register::Rip(0x100000),
            X86Register::Cr3(0x4000 | TEST_C_BIT_MASK),
            X86Register::Cr0(x86defs::X64_CR0_PE | x86defs::X64_CR0_PG),
            X86Register::Cr4(x86defs::X64_CR4_PAE),
            X86Register::Efer(x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA),
        ] {
            context.import_vp_register(register);
        }
        let vmsa = context.vmsa();
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
        let mut loader = test_loader(4, 1);
        {
            let mut importer = loader.loader();
            importer
                .import_pages(1, 1, "secret", BootPageAcceptance::SecretsPage, &[])
                .unwrap();
            import_test_registers(&mut importer);
        }
        let output = loader.finalize().unwrap();
        let directives = output.guest.directives();

        assert_eq!(directives.len(), 6);
        assert!(matches!(
            directives[0],
            IgvmDirectiveHeader::RequiredMemory { .. }
        ));
        assert!(matches!(
            directives[1],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::NORMAL,
                ref data,
                ..
            } if data.is_empty()
        ));
        assert!(matches!(
            directives[2],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::SECRETS,
                ..
            }
        ));
        assert!(matches!(
            directives[3],
            IgvmDirectiveHeader::PageData {
                data_type: IgvmPageDataType::NORMAL,
                ..
            }
        ));
        assert!(matches!(
            directives[5],
            IgvmDirectiveHeader::SnpVpContext {
                gpa: KVM_VMSA_GPA,
                ..
            }
        ));
    }

    #[test]
    fn complete_ram_emits_one_vmsa_per_processor() {
        let mut loader = test_loader(1, 4);
        import_test_registers(&mut loader.loader());
        let output = loader.finalize().unwrap();
        let vp_indexes = output
            .guest
            .directives()
            .iter()
            .filter_map(|directive| match directive {
                IgvmDirectiveHeader::SnpVpContext { vp_index, .. } => Some(*vp_index),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(vp_indexes, [0, 1, 2, 3]);
    }

    #[test]
    fn overlapping_import_does_not_mutate_existing_pages() {
        let mut loader = test_loader(4, 1);
        {
            let mut importer = loader.loader();
            importer
                .import_pages(1, 1, "first", BootPageAcceptance::Exclusive, &[0xaa])
                .unwrap();
            let error = importer
                .import_pages(
                    0,
                    2,
                    "overlap",
                    BootPageAcceptance::Exclusive,
                    &[0xbb; PAGE_SIZE as usize * 2],
                )
                .unwrap_err();
            assert!(error.to_string().contains("overlaps"));
            import_test_registers(&mut importer);
        }

        let output = loader.finalize().unwrap();
        let page = output
            .guest
            .directives()
            .iter()
            .find_map(|directive| match directive {
                IgvmDirectiveHeader::PageData { gpa, data, .. } if *gpa == PAGE_SIZE => Some(data),
                _ => None,
            })
            .unwrap();
        assert_eq!(page, &[0xaa]);
    }
}
