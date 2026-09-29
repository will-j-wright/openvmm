// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Base ACPI tables for the fixed x86 enlightened SNP Linux chipset.
//!
//! [`Topology::build`] returns DSDT, MADT and SRAT bytes, with no guest pointers.
//! After assigning permanent storage to DSDT, call [`BaseTables::fadt`].
//! Append these tables and any PCIe tables built with the existing
//! [`crate::ssdt`] and `acpi_spec::mcfg` helpers to [`crate::builder::Builder`],
//! which supplies the XSDT and RSDP.
//!
//! The fixed devices match the hosted x86 table builder: APIC and RTC DSDT
//! resources, PIC compatibility and PIT IRQ0-to-GSI2 routing in MADT, BSP
//! LINT1 NMI, and the Hyper-V PM block in FADT. CPUs have contiguous APIC IDs
//! starting at zero, all CPUs and RAM are on NUMA node zero, and each present
//! COM port uses its fixed I/O port and IRQ. No VMBus, watchdog, PSP, IOMMU,
//! SLIT or PPTT is described.

use crate::builder::OemInfo;
use crate::builder::Table;
use crate::dsdt;
use acpi_spec::fadt;
use acpi_spec::hyperv;
use acpi_spec::madt;
use acpi_spec::srat;
use alloc::vec;
use alloc::vec::Vec;
use x86defs::apic::APIC_BASE_ADDRESS;
use x86defs::serial::COM_BASES;
use x86defs::serial::COM_IRQS;
use zerocopy::IntoBytes;

/// Upper bound for DSDT + FADT + MADT + SRAT, including 8-byte table padding.
///
/// This does not include PCIe tables, XSDT/RSDP or temporary heap allocations.
pub const MAX_BASE_TABLE_BYTES: usize = 32 * 1024;

/// The hardware that the base tables describe.
#[derive(Clone, Copy, Debug)]
pub struct Topology {
    /// The number of CPUs, with APIC IDs 0 through `cpu_count - 1`.
    pub cpu_count: u8,
    /// The end of the single RAM range, which starts at address zero.
    pub ram_end: u64,
    /// Which of COM1 through COM4 are present.
    pub com_ports: [bool; 4],
}

impl Topology {
    /// Builds the pointer-free base tables.
    ///
    /// The returned base tables fit [`MAX_BASE_TABLE_BYTES`].
    pub fn build(&self, oem: &OemInfo) -> BaseTables {
        let mut dsdt = dsdt::Dsdt::new();
        dsdt.add_object(&dsdt::NamedObject::new(
            b"\\_S0",
            &dsdt::Package(vec![0, 0]),
        ));
        dsdt.add_object(&dsdt::NamedObject::new(
            b"\\_S5",
            &dsdt::Package(vec![0, 0]),
        ));
        dsdt.add_apic();
        for (index, _) in self.com_ports.iter().enumerate().filter(|(_, p)| **p) {
            let uid = index as u8 + 1;
            let name = [b'\\', b'_', b'S', b'B', b'.', b'U', b'A', b'R', b'0' + uid];
            let ddn = [b'C', b'O', b'M', b'0' + uid];
            dsdt.add_uart_shared(
                &name,
                &ddn,
                uid.into(),
                COM_BASES[index],
                COM_IRQS[index].into(),
            );
        }
        dsdt.add_rtc();
        for uid in 1..=self.cpu_count {
            let name = [
                b'P',
                b'0' + uid / 100,
                b'0' + (uid / 10) % 10,
                b'0' + uid % 10,
            ];
            let mut cpu = dsdt::Device::new(&name);
            cpu.add_object(&dsdt::NamedString::new(b"_HID", b"ACPI0007"));
            cpu.add_object(&dsdt::NamedInteger::new(b"_UID", uid.into()));
            let mut sta = dsdt::Method::new(b"_STA");
            sta.add_operation(&dsdt::ReturnOp {
                result: dsdt::encode_integer(0xf),
            });
            cpu.add_object(&sta);
            dsdt.add_object(&cpu);
        }

        let mut madt_entries = Vec::with_capacity(
            size_of::<madt::MadtIoApic>()
                + 2 * size_of::<madt::MadtInterruptSourceOverride>()
                + size_of::<madt::MadtLocalNmiSource>()
                + usize::from(self.cpu_count) * size_of::<madt::MadtApic>(),
        );
        madt_entries.extend_from_slice(
            madt::MadtIoApic {
                io_apic_id: 0,
                io_apic_address: hyperv::IOAPIC_BASE_ADDRESS,
                ..madt::MadtIoApic::new()
            }
            .as_bytes(),
        );
        madt_entries.extend_from_slice(
            madt::MadtInterruptSourceOverride::new(
                hyperv::DEFAULT_ACPI_IRQ as u8,
                hyperv::DEFAULT_ACPI_IRQ,
                Some(madt::InterruptPolarity::ActiveHigh),
                Some(madt::InterruptTriggerMode::Level),
            )
            .as_bytes(),
        );
        madt_entries
            .extend_from_slice(madt::MadtInterruptSourceOverride::new(0, 2, None, None).as_bytes());
        madt_entries.extend_from_slice(madt::MadtLocalNmiSource::new().as_bytes());
        let mut srat_entries = Vec::with_capacity(
            usize::from(self.cpu_count) * size_of::<srat::SratApic>()
                + size_of::<srat::SratMemory>(),
        );
        for apic_id in 0..self.cpu_count {
            madt_entries.extend_from_slice(
                madt::MadtApic {
                    apic_id,
                    acpi_processor_uid: apic_id + 1,
                    flags: madt::MADT_APIC_ENABLED,
                    ..madt::MadtApic::new()
                }
                .as_bytes(),
            );
            srat_entries.extend_from_slice(srat::SratApic::new(apic_id, 0).as_bytes());
        }
        srat_entries.extend_from_slice(srat::SratMemory::new(0, self.ram_end, 0).as_bytes());
        BaseTables {
            dsdt: dsdt.to_bytes(),
            madt: Table::new_dyn(
                5,
                None,
                &madt::Madt {
                    apic_addr: APIC_BASE_ADDRESS,
                    flags: madt::MADT_PCAT_COMPAT,
                },
                &[&madt_entries],
            )
            .to_vec(oem),
            srat: Table::new_dyn(
                srat::SRAT_REVISION,
                None,
                &srat::SratHeader::new(),
                &[&srat_entries],
            )
            .to_vec(oem),
        }
    }
}

/// Checksummed, unpadded base tables. DSDT is not an XSDT entry.
pub struct BaseTables {
    pub dsdt: Vec<u8>,
    pub madt: Vec<u8>,
    pub srat: Vec<u8>,
}

impl BaseTables {
    /// Builds a checksummed FADT referring to DSDT's permanent physical address.
    ///
    /// The legacy 32-bit DSDT pointer stays zero, as in the hosted builder.
    /// Only the extended pointer is used, including for DSDT above 4 GiB.
    pub fn fadt(&self, dsdt_address: u64, oem: &OemInfo) -> Vec<u8> {
        Table::new(6, None, &fixed_fadt(dsdt_address)).to_vec(oem)
    }
}

fn pm_register(offset: u16, bits: u8, access_size: fadt::AddressWidth) -> fadt::GenericAddress {
    fadt::GenericAddress {
        addr_space_id: fadt::AddressSpaceId::SystemIo,
        register_bit_width: bits,
        register_bit_offset: 0,
        access_size,
        address: u64::from(hyperv::DEFAULT_PM_PIO_BASE + offset),
    }
}

fn fixed_fadt(dsdt_address: u64) -> fadt::Fadt {
    use fadt::AddressWidth;
    fadt::Fadt {
        flags: fadt::FADT_WBINVD
            | fadt::FADT_PROC_C1
            | fadt::FADT_PWR_BUTTON
            | fadt::FADT_SLP_BUTTON
            | fadt::FADT_RTC_S4
            | fadt::FADT_TMR_VAL_EXT
            | fadt::FADT_RESET_REG_SUP
            | fadt::FADT_USE_PLATFORM_CLOCK,
        x_dsdt: dsdt_address,
        sci_int: hyperv::DEFAULT_ACPI_IRQ as u16,
        p_lvl2_lat: 101,
        p_lvl3_lat: 1001,
        pm1_evt_len: 4,
        x_pm1a_evt_blk: pm_register(hyperv::PM_STATUS, 32, AddressWidth::Word),
        pm1_cnt_len: 2,
        x_pm1a_cnt_blk: pm_register(hyperv::PM_CONTROL, 16, AddressWidth::Word),
        gpe0_blk_len: 4,
        x_gpe0_blk: pm_register(hyperv::PM_GPE0_STATUS, 32, AddressWidth::Word),
        reset_reg: pm_register(hyperv::PM_RESET, 8, AddressWidth::Byte),
        reset_value: hyperv::RESET_VALUE,
        pm_tmr_len: 4,
        x_pm_tmr_blk: pm_register(hyperv::PM_TIMER, 32, AddressWidth::Dword),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use test_with_tracing::test;
    use zerocopy::FromBytes;

    const OEM: OemInfo = OemInfo {
        oem_id: *b"HVLITE",
        oem_tableid: *b"HVLITETB",
        oem_revision: 0,
        creator_id: *b"MSHV",
        creator_revision: 0,
    };
    const RAM_END: u64 = 0x8000_0000;

    fn topology(cpu_count: u8, com_ports: [bool; 4]) -> Topology {
        Topology {
            cpu_count,
            ram_end: RAM_END,
            com_ports,
        }
    }

    fn check_table(bytes: &[u8], signature: &[u8; 4], revision: u8) {
        let (header, _) = acpi_spec::Header::read_from_prefix(bytes).unwrap();
        assert_eq!(&header.signature, signature);
        assert_eq!(header.length.get() as usize, bytes.len());
        assert_eq!(header.revision, revision);
        assert_eq!(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
    }

    fn contains(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn canonical_cpu_uids_affinities_and_maximum_size() {
        for count in [1u8, 2, 255] {
            let tables = topology(count, [true; 4]).build(&OEM);
            check_table(&tables.dsdt, b"DSDT", 2);
            check_table(&tables.madt, b"APIC", 5);
            check_table(&tables.srat, b"SRAT", 3);
            assert_eq!(u32_at(&tables.madt, 36), 0xfee0_0000);
            assert_eq!(u32_at(&tables.madt, 40), 1);
            // IOAPIC, SCI active-high/level, PIT override, then BSP LINT1 NMI.
            assert_eq!(
                &tables.madt[44..82],
                &[
                    1, 12, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0, 2, 10, 0, 9, 9, 0, 0, 0, 13, 0, 2,
                    10, 0, 0, 2, 0, 0, 0, 0, 0, 4, 6, 1, 0, 0, 1,
                ]
            );
            assert_eq!(tables.madt.len(), 82 + count as usize * 8);
            assert_eq!(tables.srat.len(), 48 + count as usize * 16 + 40);
            for apic_id in 0..count {
                let uid = apic_id + 1;
                let offset = 82 + apic_id as usize * 8;
                let apic =
                    madt::MadtApic::read_from_bytes(&tables.madt[offset..offset + 8]).unwrap();
                assert_eq!(apic.apic_id, apic_id);
                assert_eq!(apic.acpi_processor_uid, uid);
                assert_eq!({ apic.flags }, 1);
                let offset = 48 + apic_id as usize * 16;
                assert_eq!(
                    &tables.srat[offset..offset + 16],
                    &[0, 16, 0, apic_id, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                );
                let mut aml = format!("P{uid:03}").into_bytes();
                aml.extend_from_slice(b"\x08_HID\x0dACPI0007\0\x08_UID");
                if uid == 1 {
                    aml.push(1);
                } else {
                    aml.extend_from_slice(&[0xa, uid]);
                }
                assert!(contains(&tables.dsdt, &aml));
            }
            let offset = 48 + count as usize * 16;
            let memory = srat::SratMemory::read_from_bytes(&tables.srat[offset..]).unwrap();
            assert_eq!(memory.proximity_domain.get(), 0);
            assert_eq!(memory.low_address.get(), 0);
            assert_eq!(memory.high_address.get(), 0);
            assert_eq!(memory.low_length.get(), RAM_END as u32);
            assert_eq!(memory.high_length.get(), 0);
            assert_eq!(memory.flags.get(), 1);
            let fadt = tables.fadt(0x1000_0000, &OEM);
            let size: usize = [&tables.dsdt, &tables.madt, &tables.srat, &fadt]
                .iter()
                .map(|table| table.len().next_multiple_of(8))
                .sum();
            assert!(size <= MAX_BASE_TABLE_BYTES, "{size}");
        }
    }

    #[test]
    fn uart_presence_and_shared_irq_leave_legacy_bytes_unchanged() {
        let empty = topology(1, [false; 4]).build(&OEM);
        assert!(!contains(&empty.dsdt, b"UAR"));
        for present in 0..4 {
            let mut com_ports = [false; 4];
            com_ports[present] = true;
            let only = topology(1, com_ports).build(&OEM);
            for index in 0..4 {
                assert_eq!(
                    contains(&only.dsdt, format!("UAR{}", index + 1).as_bytes()),
                    index == present
                );
            }
        }
        let all = topology(1, [true; 4]).build(&OEM);
        for irq in [3, 4] {
            let resource = [0x89, 6, 0, 0xb, 1, irq, 0, 0, 0];
            assert_eq!(
                all.dsdt
                    .windows(resource.len())
                    .filter(|w| *w == resource)
                    .count(),
                2
            );
        }
        let mut legacy = dsdt::Dsdt::new();
        legacy.add_uart(b"\\_SB.UAR1", b"COM1", 1, 0x3f8, 4);
        let legacy = legacy.to_bytes();
        assert!(contains(&legacy, &[0x89, 6, 0, 3, 1, 4, 0, 0, 0]));
        let mut shared = dsdt::Dsdt::new();
        shared.add_uart_shared(b"\\_SB.UAR1", b"COM1", 1, 0x3f8, 4);
        let shared = shared.to_bytes();
        let differences: Vec<_> = legacy
            .iter()
            .zip(&shared)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .collect();
        assert_eq!(differences.len(), 2);
        assert_eq!(differences[0].0, 9); // checksum
        assert_eq!((*differences[1].1.0, *differences[1].1.1), (3, 11));
        for (start, length) in [(0xfee0_0000u32, 4096u32), (0xfec0_0000, 4096)] {
            let mut memory = vec![0x86, 9, 0, 1];
            memory.extend_from_slice(&start.to_le_bytes());
            memory.extend_from_slice(&length.to_le_bytes());
            assert!(contains(&all.dsdt, &memory));
        }
        assert!(contains(&all.dsdt, &[0x47, 1, 0x70, 0, 0x70, 0, 0, 2]));
        assert!(contains(&all.dsdt, &[0x89, 6, 0, 3, 1, 8, 0, 0, 0]));
        for sleep in [b"\\_S0_", b"\\_S5_"] {
            let mut aml = vec![8];
            aml.extend_from_slice(sleep);
            aml.extend_from_slice(&[0x12, 4, 2, 0, 0]);
            assert!(contains(&all.dsdt, &aml));
        }
    }

    #[test]
    fn fadt_fixed_registers_and_full_width_dsdt_pointer() {
        let tables = topology(1, [false; 4]).build(&OEM);
        for address in [0x2000, 0x1_0000_2000] {
            let fadt = tables.fadt(address, &OEM);
            check_table(&fadt, b"FACP", 6);
            assert_eq!(fadt.len(), 276);
            assert_eq!(u32_at(&fadt, 40), 0);
            assert_eq!(u64_at(&fadt, 140), address);
            assert_eq!(u16_at(&fadt, 46), 9);
            assert_eq!(&fadt[88..96], &[4, 2, 0, 4, 4, 0, 0, 0]);
            assert_eq!(u16_at(&fadt, 96), 101);
            assert_eq!(u16_at(&fadt, 98), 1001);
            assert_eq!(u32_at(&fadt, 112), 0x85b5);
            for (offset, bits, width, port) in [
                (116, 8, 1, 0x433),
                (148, 32, 2, 0x400),
                (172, 16, 2, 0x404),
                (208, 32, 3, 0x408),
                (220, 32, 2, 0x40c),
            ] {
                assert_eq!(&fadt[offset..offset + 4], &[1, bits, 0, width]);
                assert_eq!(u64_at(&fadt, offset + 4), port);
            }
            assert_eq!(fadt[128], 1);
        }
    }

    #[test]
    fn base_tables_compose_with_existing_root_builder() {
        let tables = topology(2, [false; 4]).build(&OEM);
        let base = 0x1_0000_0000;
        let mut builder = crate::builder::Builder::new(base, OEM);
        let dsdt = builder.append_raw(&tables.dsdt);
        let fadt_bytes = tables.fadt(dsdt, &OEM);
        let fadt = builder.append_raw(&fadt_bytes);
        let madt = builder.append_raw(&tables.madt);
        let srat = builder.append_raw(&tables.srat);
        let (rsdp_bytes, bytes) = builder.build();
        let rsdp = acpi_spec::Rsdp::read_from_bytes(&rsdp_bytes).unwrap();
        assert_eq!(
            rsdp_bytes[..20].iter().fold(0u8, |a, b| a.wrapping_add(*b)),
            0
        );
        assert_eq!(rsdp_bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)), 0);
        let offset = (rsdp.xsdt - base) as usize;
        let length = u32_at(&bytes, offset + 4) as usize;
        let xsdt = &bytes[offset..offset + length];
        check_table(xsdt, b"XSDT", 1);
        assert_eq!(&xsdt[36..], [fadt, madt, srat].as_bytes());
        assert_eq!(u64_at(&fadt_bytes, 140), dsdt);
        for (address, expected) in [
            (dsdt, &tables.dsdt),
            (fadt, &fadt_bytes),
            (madt, &tables.madt),
            (srat, &tables.srat),
        ] {
            assert_eq!(address % 8, 0);
            let offset = (address - base) as usize;
            assert_eq!(&bytes[offset..offset + expected.len()], expected);
        }
    }
}
