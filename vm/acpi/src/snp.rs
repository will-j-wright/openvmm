// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validated hardware topology for the fixed x86 enlightened SNP Linux chipset.
//!
//! [`Topology::new`] validates the small supported hardware contract without
//! allocating. The caller must first validate DT syntax, memory types, the
//! measured RAM interval, and unsupported devices. This is not a DT parser.

use thiserror::Error;

/// The fixed contract uses legacy APIC IDs 0 through 254.
pub const MAX_CPUS: usize = 255;
/// At most the four fixed COM ports can be present.
pub const MAX_UARTS: usize = 4;

/// One CPU decoded from DT.
#[derive(Clone, Copy, Debug)]
pub struct Cpu {
    pub apic_id: u32,
    pub numa_node: u32,
    pub enabled: bool,
}

/// The single normalized RAM interval, already compared with measured RAM.
#[derive(Clone, Copy, Debug)]
pub struct Ram {
    pub start: u64,
    pub length: u64,
    pub numa_node: u32,
}

/// A present 16550 UART decoded from DT. `uid` is the COM number (1 to 4).
#[derive(Clone, Copy, Debug)]
pub struct Uart {
    pub uid: u8,
    pub io_base: u16,
    pub length: u64,
    pub irq: u32,
}

/// An unsupported or inconsistent SNP ACPI input.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("CPU count must match the measured count in 1 through 255")]
    CpuCount,
    #[error("BSP APIC ID must be zero")]
    Bsp,
    #[error(
        "CPUs must be enabled, unique, and have contiguous APIC IDs starting at zero on node zero"
    )]
    Cpu,
    #[error("RAM must be a nonempty, page-aligned interval on node zero without address overflow")]
    Ram,
    #[error("UARTs must be unique fixed COM1 through COM4 resources")]
    Uart,
}

/// A validated topology. Construction and validation do not allocate.
#[expect(dead_code, reason = "table generation reads these fields")]
pub struct Topology {
    cpu_count: u8,
    ram: Ram,
    uarts: [Option<Uart>; MAX_UARTS],
}

impl Topology {
    /// Checks the measured CPU count, BSP, CPU set, normalized RAM and UARTs.
    ///
    /// A missing UART list is not synthesized: an empty slice means no UARTs.
    /// Duplicate I/O resources are rejected; shared IRQ3/IRQ4 are valid.
    pub fn new(
        expected_cpu_count: u32,
        bsp_apic_id: u32,
        cpus: &[Cpu],
        ram: Ram,
        uarts: &[Uart],
    ) -> Result<Self, Error> {
        if !(1..=MAX_CPUS as u32).contains(&expected_cpu_count)
            || cpus.len() != expected_cpu_count as usize
        {
            return Err(Error::CpuCount);
        }
        if bsp_apic_id != 0 {
            return Err(Error::Bsp);
        }
        let mut seen = [false; MAX_CPUS];
        for cpu in cpus {
            if cpu.apic_id >= expected_cpu_count || cpu.numa_node != 0 || !cpu.enabled {
                return Err(Error::Cpu);
            }
            if core::mem::replace(&mut seen[cpu.apic_id as usize], true) {
                return Err(Error::Cpu);
            }
        }
        if ram.numa_node != 0
            || ram.length == 0
            || !ram.start.is_multiple_of(4096)
            || !ram.length.is_multiple_of(4096)
            || ram.start.checked_add(ram.length).is_none()
        {
            return Err(Error::Ram);
        }
        if uarts.len() > MAX_UARTS {
            return Err(Error::Uart);
        }
        let mut present = [None; MAX_UARTS];
        for uart in uarts {
            let index = match uart.uid {
                1..=4 => usize::from(uart.uid - 1),
                _ => return Err(Error::Uart),
            };
            if uart.io_base != x86defs::serial::COM_BASES[index]
                || uart.irq != u32::from(x86defs::serial::COM_IRQS[index])
                || uart.length != u64::from(x86defs::serial::COM_REGISTER_COUNT)
                || present[index].is_some()
            {
                return Err(Error::Uart);
            }
            present[index] = Some(*uart);
        }
        Ok(Self {
            cpu_count: expected_cpu_count as u8,
            ram,
            uarts: present,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use test_with_tracing::test;

    const RAM: Ram = Ram {
        start: 0,
        length: 0x8000_0000,
        numa_node: 0,
    };
    const UARTS: [Uart; 4] = [
        Uart {
            uid: 1,
            io_base: 0x3f8,
            length: 8,
            irq: 4,
        },
        Uart {
            uid: 2,
            io_base: 0x2f8,
            length: 8,
            irq: 3,
        },
        Uart {
            uid: 3,
            io_base: 0x3e8,
            length: 8,
            irq: 4,
        },
        Uart {
            uid: 4,
            io_base: 0x2e8,
            length: 8,
            irq: 3,
        },
    ];

    fn cpus(count: u32) -> Vec<Cpu> {
        (0..count)
            .map(|apic_id| Cpu {
                apic_id,
                numa_node: 0,
                enabled: true,
            })
            .collect()
    }

    #[test]
    fn rejects_invalid_cpu_contract() {
        for (expected, count) in [(0, 0), (256, 256), (1, 2), (2, 1)] {
            assert_eq!(
                Topology::new(expected, 0, &cpus(count), RAM, &[]).err(),
                Some(Error::CpuCount)
            );
        }
        assert_eq!(
            Topology::new(1, 1, &cpus(1), RAM, &[]).err(),
            Some(Error::Bsp)
        );
        for bad in [
            Cpu {
                apic_id: 2,
                numa_node: 0,
                enabled: true,
            },
            Cpu {
                apic_id: u32::MAX,
                numa_node: 0,
                enabled: true,
            },
            Cpu {
                apic_id: 1,
                numa_node: 1,
                enabled: true,
            },
            Cpu {
                apic_id: 1,
                numa_node: 0,
                enabled: false,
            },
            Cpu {
                apic_id: 0,
                numa_node: 0,
                enabled: true,
            },
        ] {
            let mut cpus = cpus(2);
            cpus[1] = bad;
            assert_eq!(Topology::new(2, 0, &cpus, RAM, &[]).err(), Some(Error::Cpu));
        }
    }

    #[test]
    fn rejects_invalid_ram_and_uart_resources() {
        for ram in [
            Ram { length: 0, ..RAM },
            Ram { start: 1, ..RAM },
            Ram {
                length: 4095,
                ..RAM
            },
            Ram {
                numa_node: 1,
                ..RAM
            },
            Ram {
                start: u64::MAX - 4095,
                length: 4096,
                ..RAM
            },
        ] {
            assert_eq!(
                Topology::new(1, 0, &cpus(1), ram, &[]).err(),
                Some(Error::Ram)
            );
        }
        for uart in [
            Uart { uid: 0, ..UARTS[0] },
            Uart { uid: 5, ..UARTS[0] },
            Uart {
                io_base: 0x3f9,
                ..UARTS[0]
            },
            Uart {
                io_base: 0x2f8,
                ..UARTS[0]
            },
            Uart {
                length: 0,
                ..UARTS[0]
            },
            Uart {
                length: 9,
                ..UARTS[0]
            },
            Uart { irq: 3, ..UARTS[0] },
        ] {
            assert_eq!(
                Topology::new(1, 0, &cpus(1), RAM, &[uart]).err(),
                Some(Error::Uart)
            );
        }
        for uarts in [&[UARTS[0]; 2][..], &[UARTS[0]; 5][..]] {
            assert_eq!(
                Topology::new(1, 0, &cpus(1), RAM, uarts).err(),
                Some(Error::Uart)
            );
        }
    }
}
