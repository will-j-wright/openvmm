// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A minimal ACPI builder for `no_std` boot environments.
//!
//! [`Platform::build`] returns the DSDT, MADT, and SRAT for a simple platform:
//! CPUs with contiguous IDs starting at zero, one RAM range, and the fixed
//! devices of the chosen [`Arch`]. All CPUs and RAM are on NUMA node zero.
//! After assigning permanent storage to the DSDT, call [`BaseTables::fadt`].
//! Append these tables and any PCIe tables built with the [`crate::ssdt`] and
//! `acpi_spec::mcfg` helpers to [`crate::builder::Builder`], which supplies
//! the XSDT and RSDP.
//!
//! Unlike the hosted builder in `vmm_core`, this builder needs only `alloc`.
//! Only x86 is supported today.

use crate::builder::OemInfo;
use crate::builder::Table;
use crate::dsdt;
use acpi_spec::fadt;
use acpi_spec::hyperv;
use acpi_spec::madt;
use acpi_spec::srat;
use alloc::vec;
use alloc::vec::Vec;
use memory_range::MemoryRange;
use x86defs::apic::APIC_BASE_ADDRESS;
use x86defs::serial::COM_BASES;
use x86defs::serial::COM_IRQS;
use zerocopy::IntoBytes;

/// Upper bound for DSDT + FADT + MADT + SRAT, including 8-byte table padding.
///
/// This does not include PCIe tables, XSDT/RSDP or temporary heap allocations.
pub const MAX_BASE_TABLE_BYTES: usize = 32 * 1024;

/// The platform that the base tables describe.
#[derive(Clone, Copy, Debug)]
pub struct Platform {
    /// The number of CPUs, with IDs 0 through `cpu_count - 1`.
    pub cpu_count: u8,
    /// The single RAM range.
    pub ram: MemoryRange,
    /// The architecture-specific devices.
    pub arch: Arch,
}

/// The architecture-specific part of a [`Platform`].
#[derive(Clone, Copy, Debug)]
pub enum Arch {
    /// An x86 platform.
    X86(X86),
}

/// An x86 platform with the fixed Hyper-V-compatible chipset.
///
/// The devices match the hosted x86 table builder: APIC and RTC DSDT
/// resources, PIC compatibility and PIT IRQ0-to-GSI2 routing in the MADT, a
/// BSP LINT1 NMI, and the Hyper-V PM block in the FADT. Each present COM port
/// uses its fixed I/O port and IRQ. The MADT uses legacy APIC entries, so the
/// APIC IDs must fit in a `u8`.
#[derive(Clone, Copy, Debug)]
pub struct X86 {
    /// Which of COM1 through COM4 are present.
    pub com_ports: [bool; 4],
}

impl Platform {
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
        match self.arch {
            Arch::X86(x86) => x86.add_dsdt_devices(&mut dsdt),
        }
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

        let (madt, mut srat_entries) = match self.arch {
            Arch::X86(_) => (
                X86::madt(self.cpu_count, oem),
                X86::srat_cpus(self.cpu_count),
            ),
        };
        srat_entries.extend_from_slice(
            srat::SratMemory::new(self.ram.start(), self.ram.len(), 0).as_bytes(),
        );
        BaseTables {
            dsdt: dsdt.to_bytes(),
            madt,
            srat: Table::new_dyn(
                srat::SRAT_REVISION,
                None,
                &srat::SratHeader::new(),
                &[&srat_entries],
            )
            .to_vec(oem),
            arch: self.arch,
        }
    }
}

impl X86 {
    fn add_dsdt_devices(&self, dsdt: &mut dsdt::Dsdt) {
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
    }

    fn madt(cpu_count: u8, oem: &OemInfo) -> Vec<u8> {
        let mut entries = Vec::with_capacity(
            size_of::<madt::MadtIoApic>()
                + 2 * size_of::<madt::MadtInterruptSourceOverride>()
                + size_of::<madt::MadtLocalNmiSource>()
                + usize::from(cpu_count) * size_of::<madt::MadtApic>(),
        );
        entries.extend_from_slice(
            madt::MadtIoApic {
                io_apic_id: 0,
                io_apic_address: hyperv::IOAPIC_BASE_ADDRESS,
                ..madt::MadtIoApic::new()
            }
            .as_bytes(),
        );
        entries.extend_from_slice(
            madt::MadtInterruptSourceOverride::new(
                hyperv::DEFAULT_ACPI_IRQ as u8,
                hyperv::DEFAULT_ACPI_IRQ,
                Some(madt::InterruptPolarity::ActiveHigh),
                Some(madt::InterruptTriggerMode::Level),
            )
            .as_bytes(),
        );
        entries
            .extend_from_slice(madt::MadtInterruptSourceOverride::new(0, 2, None, None).as_bytes());
        entries.extend_from_slice(madt::MadtLocalNmiSource::new().as_bytes());
        for apic_id in 0..cpu_count {
            entries.extend_from_slice(
                madt::MadtApic {
                    apic_id,
                    acpi_processor_uid: apic_id + 1,
                    flags: madt::MADT_APIC_ENABLED,
                    ..madt::MadtApic::new()
                }
                .as_bytes(),
            );
        }
        Table::new_dyn(
            5,
            None,
            &madt::Madt {
                apic_addr: APIC_BASE_ADDRESS,
                flags: madt::MADT_PCAT_COMPAT,
            },
            &[&entries],
        )
        .to_vec(oem)
    }

    /// Returns the SRAT CPU entries, with room for the memory entry.
    fn srat_cpus(cpu_count: u8) -> Vec<u8> {
        let mut entries = Vec::with_capacity(
            usize::from(cpu_count) * size_of::<srat::SratApic>() + size_of::<srat::SratMemory>(),
        );
        for apic_id in 0..cpu_count {
            entries.extend_from_slice(srat::SratApic::new(apic_id, 0).as_bytes());
        }
        entries
    }

    fn fadt(dsdt_address: u64) -> fadt::Fadt {
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
}

/// Checksummed, unpadded base tables. DSDT is not an XSDT entry.
pub struct BaseTables {
    pub dsdt: Vec<u8>,
    pub madt: Vec<u8>,
    pub srat: Vec<u8>,
    arch: Arch,
}

impl BaseTables {
    /// Builds a checksummed FADT referring to DSDT's permanent physical address.
    ///
    /// The legacy 32-bit DSDT pointer stays zero, as in the hosted builder.
    /// Only the extended pointer is used, including for DSDT above 4 GiB.
    pub fn fadt(&self, dsdt_address: u64, oem: &OemInfo) -> Vec<u8> {
        let fadt = match self.arch {
            Arch::X86(_) => X86::fadt(dsdt_address),
        };
        Table::new(6, None, &fadt).to_vec(oem)
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

// `vmm_core`'s `minimal_tables_match_hosted_fixed_chipset` checks that the
// MADT, SRAT, FADT, and CPU devices match the hosted builder byte for byte.
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

    fn x86(cpu_count: u8, com_ports: [bool; 4]) -> BaseTables {
        Platform {
            cpu_count,
            ram: MemoryRange::new(0..0x8000_0000),
            arch: Arch::X86(X86 { com_ports }),
        }
        .build(&OEM)
    }

    fn contains(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn largest_tables_are_valid_and_fit() {
        let tables = x86(u8::MAX, [true; 4]);
        let fadt = tables.fadt(0x1_0000_0000, &OEM);
        let mut size = 0;
        for (bytes, signature) in [
            (&tables.dsdt, b"DSDT"),
            (&tables.madt, b"APIC"),
            (&tables.srat, b"SRAT"),
            (&fadt, b"FACP"),
        ] {
            let (header, _) = acpi_spec::Header::read_from_prefix(bytes).unwrap();
            assert_eq!(&header.signature, signature);
            assert_eq!(header.length.get() as usize, bytes.len());
            assert_eq!(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
            size += bytes.len().next_multiple_of(8);
        }
        assert!(size <= MAX_BASE_TABLE_BYTES, "{size}");
    }

    #[test]
    fn only_present_com_ports_use_shared_irqs() {
        let tables = x86(1, [true, false, false, true]);
        for (uid, present) in [(1, true), (2, false), (3, false), (4, true)] {
            assert_eq!(
                contains(&tables.dsdt, format!("UAR{uid}").as_bytes()),
                present
            );
        }
        // An IRQ descriptor with the shared bit set, for IRQ 4 (COM1) and 3 (COM4).
        for irq in [4, 3] {
            assert!(contains(&tables.dsdt, &[0x89, 6, 0, 0xb, 1, irq, 0, 0, 0]));
        }
    }
}
