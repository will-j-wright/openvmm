// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VFIO-backed PCI device assignment for OpenVMM.
//!
//! This crate implements a [`ChipsetDevice`] that proxies PCI config space
//! accesses to a physical device opened via Linux VFIO. The device appears
//! as a standard PCIe endpoint to the guest.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::mmio::MmioIntercept;
use chipset_device::pci::PciConfigSpace;
use inspect::InspectMut;
use pci_core::bar_mapping::BarMappings;
use pci_core::spec::cfg_space;
use std::fs::File;
use std::os::unix::fs::FileExt;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmcore::save_restore::SavedStateNotSupported;

/// A PCI device backed by a VFIO device file.
///
/// Config space reads/writes are proxied to the physical device via the VFIO
/// config region. BARs are cached locally so the guest can probe sizes without
/// hitting hardware on every access.
#[derive(InspectMut)]
pub struct VfioAssignedPciDevice {
    /// The PCI BDF string (e.g., "0000:3f7a:00:00.0") for diagnostics.
    #[inspect(display)]
    pci_id: String,

    /// The VFIO device file descriptor, used for config space read/write.
    #[inspect(skip)]
    device_file: File,

    /// Offset into the VFIO device fd where the PCI config region starts.
    #[inspect(hex)]
    config_offset: u64,

    /// Size of the config space region.
    #[inspect(hex)]
    config_size: u64,

    /// BAR masks as read from the physical device (write 0xFFFFFFFF, read back).
    #[inspect(skip)]
    bar_masks: [u32; 6],

    /// Current BAR values as seen by the guest.
    #[inspect(skip)]
    bars: [u32; 6],

    /// Low bits of each BAR that encode type/prefetch flags.
    #[inspect(skip)]
    bar_flags: [u32; 6],

    /// Current MMIO-enabled state (from PCI Command register bit 1).
    mmio_enabled: bool,

    /// Decoded BAR mappings when MMIO is enabled.
    #[inspect(skip)]
    active_bars: BarMappings,
}

/// Parameters for creating a [`VfioAssignedPciDevice`].
pub struct VfioAssignedPciDeviceConfig {
    /// PCI BDF string (e.g., "3f7a:00:00.0").
    pub pci_id: String,
    /// The opened VFIO device file (from `vfio_sys::Group::open_device`).
    pub device_file: File,
    /// Config region info from `vfio_sys::Device::region_info(CONFIG_REGION_INDEX)`.
    pub config_offset: u64,
    /// Config region size.
    pub config_size: u64,
}

impl VfioAssignedPciDevice {
    /// Create a new VFIO assigned PCI device.
    ///
    /// Probes the physical device's BAR masks by writing 0xFFFFFFFF to each BAR
    /// and reading back the result (standard PCI BAR sizing).
    pub fn new(config: VfioAssignedPciDeviceConfig) -> anyhow::Result<Self> {
        let device_file = config.device_file;
        let config_offset = config.config_offset;
        let config_size = config.config_size;

        // Read original BAR values and probe masks.
        let mut bar_masks = [0u32; 6];
        let mut bars = [0u32; 6];
        let mut bar_flags = [0u32; 6];

        let mut i = 0;
        while i < 6 {
            let offset = 0x10 + (i as u16) * 4;

            // Save original value.
            let original = read_config_u32(&device_file, config_offset, config_size, offset)?;
            bars[i] = original;

            // Write all-ones to probe the mask.
            write_config_u32(&device_file, config_offset, config_size, offset, !0)?;
            let mask = read_config_u32(&device_file, config_offset, config_size, offset)?;

            // Restore original value.
            write_config_u32(&device_file, config_offset, config_size, offset, original)?;

            bar_masks[i] = mask;
            bar_flags[i] = original & 0xf;

            // Skip the upper 32 bits of a 64-bit BAR.
            if cfg_space::BarEncodingBits::from_bits(mask).type_64_bit() {
                if i + 1 < 6 {
                    let upper_offset = 0x10 + ((i + 1) as u16) * 4;
                    let upper_original =
                        read_config_u32(&device_file, config_offset, config_size, upper_offset)?;
                    bars[i + 1] = upper_original;

                    write_config_u32(&device_file, config_offset, config_size, upper_offset, !0)?;
                    let upper_mask =
                        read_config_u32(&device_file, config_offset, config_size, upper_offset)?;
                    write_config_u32(
                        &device_file,
                        config_offset,
                        config_size,
                        upper_offset,
                        upper_original,
                    )?;

                    bar_masks[i + 1] = upper_mask;
                    bar_flags[i + 1] = 0;
                }
                i += 2;
            } else {
                i += 1;
            }
        }

        tracing::info!(
            pci_id = config.pci_id.as_str(),
            ?bar_masks,
            "VFIO assigned PCI device initialized"
        );

        Ok(Self {
            pci_id: config.pci_id,
            device_file,
            config_offset,
            config_size,
            bar_masks,
            bars,
            bar_flags,
            mmio_enabled: false,
            active_bars: BarMappings::default(),
        })
    }

    fn read_phys_config(&self, offset: u16) -> u32 {
        read_config_u32(
            &self.device_file,
            self.config_offset,
            self.config_size,
            offset,
        )
        .unwrap_or(!0)
    }

    fn write_phys_config(&self, offset: u16, value: u32) {
        if let Err(e) = write_config_u32(
            &self.device_file,
            self.config_offset,
            self.config_size,
            offset,
            value,
        ) {
            tracelimit::warn_ratelimited!(
                offset,
                error = format!("{e:#}").as_str(),
                "VFIO config space write failed"
            );
        }
    }
}

fn read_config_u32(
    file: &File,
    config_offset: u64,
    config_size: u64,
    offset: u16,
) -> anyhow::Result<u32> {
    if (offset as u64) + 4 > config_size {
        anyhow::bail!("config read offset {offset:#x} out of range");
    }
    let mut buf = [0u8; 4];
    file.read_at(&mut buf, config_offset + offset as u64)?;
    Ok(u32::from_ne_bytes(buf))
}

fn write_config_u32(
    file: &File,
    config_offset: u64,
    config_size: u64,
    offset: u16,
    value: u32,
) -> anyhow::Result<()> {
    if (offset as u64) + 4 > config_size {
        anyhow::bail!("config write offset {offset:#x} out of range");
    }
    file.write_at(&value.to_ne_bytes(), config_offset + offset as u64)?;
    Ok(())
}

impl ChangeDeviceState for VfioAssignedPciDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {
        self.mmio_enabled = false;
        self.active_bars = BarMappings::default();
    }
}

impl ChipsetDevice for VfioAssignedPciDevice {
    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        Some(self)
    }

    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }
}

impl PciConfigSpace for VfioAssignedPciDevice {
    fn pci_cfg_read(&mut self, offset: u16, value: &mut u32) -> IoResult {
        *value = match offset {
            // BAR registers: return locally cached values.
            0x10 | 0x14 | 0x18 | 0x1c | 0x20 | 0x24 => {
                let i = (offset - 0x10) as usize / 4;
                self.bars[i]
            }
            // Everything else: read from physical device.
            _ => self.read_phys_config(offset),
        };

        IoResult::Ok
    }

    fn pci_cfg_write(&mut self, offset: u16, value: u32) -> IoResult {
        match offset {
            // Command register: track MMIO enable/disable.
            4 => {
                let command = cfg_space::Command::from_bits(value as u16);
                let new_mmio_enabled = command.mmio_enabled();

                if new_mmio_enabled && !self.mmio_enabled {
                    self.active_bars = BarMappings::parse(&self.bars, &self.bar_masks);
                    tracing::debug!(pci_id = self.pci_id.as_str(), "MMIO enabled by guest");
                } else if !new_mmio_enabled && self.mmio_enabled {
                    self.active_bars = BarMappings::default();
                    tracing::debug!(pci_id = self.pci_id.as_str(), "MMIO disabled by guest");
                }

                self.mmio_enabled = new_mmio_enabled;
                self.write_phys_config(offset, value);
            }
            // BAR registers: mask and cache locally.
            0x10 | 0x14 | 0x18 | 0x1c | 0x20 | 0x24 => {
                let i = (offset - 0x10) as usize / 4;
                self.bars[i] = (value & self.bar_masks[i]) | self.bar_flags[i];
            }
            // All other registers: pass through to physical device.
            _ => {
                self.write_phys_config(offset, value);
            }
        }

        IoResult::Ok
    }
}

impl MmioIntercept for VfioAssignedPciDevice {
    fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> IoResult {
        // For now, return all-ones. Full BAR MMIO passthrough is a future step.
        if let Some((_bar, _offset)) = self.active_bars.find(addr) {
            tracelimit::warn_ratelimited!(
                addr,
                len = data.len(),
                pci_id = self.pci_id.as_str(),
                "MMIO read not yet implemented for VFIO device"
            );
        }
        data.fill(!0);
        IoResult::Ok
    }

    fn mmio_write(&mut self, addr: u64, data: &[u8]) -> IoResult {
        if let Some((_bar, _offset)) = self.active_bars.find(addr) {
            tracelimit::warn_ratelimited!(
                addr,
                len = data.len(),
                pci_id = self.pci_id.as_str(),
                "MMIO write not yet implemented for VFIO device"
            );
        }
        IoResult::Ok
    }
}

impl SaveRestore for VfioAssignedPciDevice {
    type SavedState = SavedStateNotSupported;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Err(SaveError::NotSupported)
    }

    fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
        match state {}
    }
}
