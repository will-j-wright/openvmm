// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VFIO-backed PCI device assignment for OpenVMM.
//!
//! This crate implements a [`ChipsetDevice`] that proxies PCI config space
//! and BAR MMIO accesses to a physical device opened via Linux VFIO. The device
//! appears as a standard PCIe endpoint to the guest. MSI-X table and PBA
//! accesses are intercepted and handled by a software emulator; all other BAR
//! MMIO is proxied directly to hardware.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::mmio::MmioIntercept;
use chipset_device::pci::PciConfigSpace;
use inspect::InspectMut;
use pci_core::bar_mapping::BarMappings;
use pci_core::capabilities::PciCapability;
use pci_core::capabilities::msix::MsixEmulator;
use pci_core::msi::MsiTarget;
use pci_core::spec::cfg_space;
use std::fs::File;
use std::os::unix::fs::FileExt;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmcore::save_restore::SavedStateNotSupported;

/// MSI-X capability ID per PCI spec.
const PCI_CAP_ID_MSIX: u8 = 0x11;

/// VFIO BAR region information (offset and size within the device fd).
#[derive(Debug, Clone, Copy)]
struct BarRegion {
    /// Offset within the VFIO device fd where this BAR region starts.
    vfio_offset: u64,
    /// Size of the BAR region in bytes.
    size: u64,
}

/// MSI-X emulation state, discovered from the physical device's capabilities.
struct MsixInfo {
    /// Software MSI-X table emulator (handles table entries, PBA,
    /// enable/disable state transitions).
    emulator: MsixEmulator,
    /// MSI-X PCI capability handler (shared state with emulator; used to
    /// forward config space writes so the emulator tracks enable/disable).
    capability: Box<dyn PciCapability>,
    /// Offset of the MSI-X capability in PCI config space.
    cap_offset: u16,
    /// BAR index containing the MSI-X table.
    table_bar: u8,
    /// Byte offset of the MSI-X table within its BAR.
    table_offset: u32,
    /// Total size of the MSI-X table in bytes (vector_count * 16).
    table_size: u64,
    /// BAR index containing the PBA.
    pba_bar: u8,
    /// Byte offset of the PBA within its BAR.
    pba_offset: u32,
    /// Total size of the PBA in bytes.
    pba_size: u64,
}

/// A PCI device backed by a VFIO device file.
///
/// Config space reads/writes are proxied to the physical device via the VFIO
/// config region. BARs are cached locally so the guest can probe sizes without
/// hitting hardware on every access. MSI-X table and PBA MMIO accesses are
/// intercepted and handled by a software emulator; all other BAR MMIO is
/// proxied to the physical device via pread/pwrite on the VFIO device fd.
#[derive(InspectMut)]
pub struct VfioAssignedPciDevice {
    /// The PCI BDF string (e.g., "0000:3f7a:00:00.0") for diagnostics.
    #[inspect(display)]
    pci_id: String,

    /// The VFIO device file descriptor, used for config space and BAR MMIO.
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

    /// VFIO region info per BAR for MMIO proxying via pread/pwrite.
    #[inspect(skip)]
    bar_regions: [Option<BarRegion>; 6],

    /// MSI-X emulation state (None if device has no MSI-X capability).
    #[inspect(skip)]
    msix: Option<MsixInfo>,
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
    /// MSI target for interrupt delivery (from an `MsiConnection`).
    pub msi_target: MsiTarget,
    /// VFIO region info per BAR: `(offset_in_fd, size)`. `None` if the BAR
    /// region does not exist or has zero size.
    pub bar_info: [Option<(u64, u64)>; 6],
}

impl VfioAssignedPciDevice {
    /// Create a new VFIO assigned PCI device.
    ///
    /// Probes the physical device's BAR masks by writing 0xFFFFFFFF to each BAR
    /// and reading back the result (standard PCI BAR sizing). Discovers MSI-X
    /// capability if present and creates a software emulator for it.
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

        // Convert bar_info to BarRegion array.
        let bar_regions = config.bar_info.map(|info| {
            info.map(|(offset, size)| BarRegion {
                vfio_offset: offset,
                size,
            })
        });

        // Discover MSI-X capability from physical device config space.
        let msix = discover_msix(&device_file, config_offset, config_size, &config.msi_target);

        tracing::info!(
            pci_id = config.pci_id.as_str(),
            ?bar_masks,
            has_msix = msix.is_some(),
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
            bar_regions,
            msix,
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

    /// Map a BAR + offset to an MsixEmulator offset, if the access falls
    /// within the MSI-X table or PBA region.
    fn msix_emulator_offset(&self, bar: u8, offset: u64) -> Option<u64> {
        let msix = self.msix.as_ref()?;

        // Check MSI-X table region.
        if bar == msix.table_bar {
            let table_start = msix.table_offset as u64;
            let table_end = table_start + msix.table_size;
            if offset >= table_start && offset < table_end {
                // Emulator table starts at offset 0.
                return Some(offset - table_start);
            }
        }

        // Check PBA region.
        if bar == msix.pba_bar {
            let pba_start = msix.pba_offset as u64;
            let pba_end = pba_start + msix.pba_size;
            if offset >= pba_start && offset < pba_end {
                // In the emulator, PBA starts right after the table.
                let emu_pba_start = msix.table_size;
                return Some(emu_pba_start + (offset - pba_start));
            }
        }

        None
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

/// Walk the PCI capabilities list to find an MSI-X capability. If found,
/// create an [`MsixEmulator`] and return the discovery info.
fn discover_msix(
    device_file: &File,
    config_offset: u64,
    config_size: u64,
    msi_target: &MsiTarget,
) -> Option<MsixInfo> {
    // Read the Capabilities Pointer (offset 0x34). Bottom 2 bits are reserved.
    let cap_ptr_dword = read_config_u32(device_file, config_offset, config_size, 0x34).ok()?;
    let mut cap_ptr = (cap_ptr_dword & 0xFC) as u16;

    while cap_ptr != 0 {
        let header = read_config_u32(device_file, config_offset, config_size, cap_ptr).ok()?;
        let cap_id = (header & 0xFF) as u8;
        let next_ptr = ((header >> 8) & 0xFC) as u16;

        if cap_id == PCI_CAP_ID_MSIX {
            // Message Control is in the upper 16 bits of the first DWORD.
            let msg_ctrl = (header >> 16) as u16;
            let table_count = (msg_ctrl & 0x7FF) + 1;

            // Table Offset/BIR (second DWORD of the capability).
            let table_dword =
                read_config_u32(device_file, config_offset, config_size, cap_ptr + 4).ok()?;
            let table_bir = (table_dword & 0x7) as u8;
            let table_offset = table_dword & !0x7;

            // PBA Offset/BIR (third DWORD of the capability).
            let pba_dword =
                read_config_u32(device_file, config_offset, config_size, cap_ptr + 8).ok()?;
            let pba_bir = (pba_dword & 0x7) as u8;
            let pba_offset = pba_dword & !0x7;

            let table_size = table_count as u64 * 16;
            // PBA: one bit per vector, rounded up to QWORD boundary.
            let pba_size = (table_count as u64).div_ceil(64) * 8;

            let (emulator, msix_cap) = MsixEmulator::new(table_bir, table_count, msi_target);

            tracing::info!(
                table_count,
                table_bir,
                table_offset,
                pba_bir,
                pba_offset,
                cap_offset = cap_ptr,
                "discovered MSI-X capability"
            );

            return Some(MsixInfo {
                emulator,
                capability: Box::new(msix_cap),
                cap_offset: cap_ptr,
                table_bar: table_bir,
                table_offset,
                table_size,
                pba_bar: pba_bir,
                pba_offset,
                pba_size,
            });
        }

        cap_ptr = next_ptr;
    }

    None
}

/// Read from the MSI-X emulator at the given offset, handling sub-DWORD
/// accesses by aligning to u32 boundaries.
fn read_msix_emulator(emulator: &MsixEmulator, offset: u64, data: &mut [u8]) {
    let aligned = offset & !3;
    let shift = (offset & 3) as usize;
    let val = emulator.read_u32(aligned);
    let bytes = val.to_le_bytes();
    let first_chunk = data.len().min(4 - shift);
    data[..first_chunk].copy_from_slice(&bytes[shift..shift + first_chunk]);

    // Handle reads that span a u32 boundary.
    if first_chunk < data.len() {
        let next_val = emulator.read_u32(aligned + 4);
        let next_bytes = next_val.to_le_bytes();
        let remaining = data.len() - first_chunk;
        data[first_chunk..first_chunk + remaining].copy_from_slice(&next_bytes[..remaining]);
    }
}

/// Write to the MSI-X emulator at the given offset, handling sub-DWORD
/// accesses via read-modify-write.
fn write_msix_emulator(emulator: &mut MsixEmulator, offset: u64, data: &[u8]) {
    let aligned = offset & !3;
    let shift = (offset & 3) as usize;
    let first_chunk = data.len().min(4 - shift);

    if first_chunk == 4 && shift == 0 {
        // Fast path: aligned u32 write.
        let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        emulator.write_u32(aligned, val);
    } else {
        // Read-modify-write for sub-DWORD access.
        let mut current = emulator.read_u32(aligned).to_le_bytes();
        current[shift..shift + first_chunk].copy_from_slice(&data[..first_chunk]);
        emulator.write_u32(aligned, u32::from_le_bytes(current));
    }

    // Handle writes that span a u32 boundary.
    if first_chunk < data.len() {
        let remaining = data.len() - first_chunk;
        let mut next = emulator.read_u32(aligned + 4).to_le_bytes();
        next[..remaining].copy_from_slice(&data[first_chunk..]);
        emulator.write_u32(aligned + 4, u32::from_le_bytes(next));
    }
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
                // Intercept MSI-X capability writes to track enable/disable
                // state in the software emulator.
                if let Some(msix) = &mut self.msix {
                    if offset == msix.cap_offset {
                        msix.capability.write_u32(0, value);
                    }
                }
                self.write_phys_config(offset, value);
            }
        }

        IoResult::Ok
    }
}

impl MmioIntercept for VfioAssignedPciDevice {
    fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> IoResult {
        if let Some((bar, offset)) = self.active_bars.find(addr) {
            // Check if this access falls in the MSI-X table or PBA.
            if let Some(emu_offset) = self.msix_emulator_offset(bar, offset) {
                read_msix_emulator(&self.msix.as_ref().unwrap().emulator, emu_offset, data);
                return IoResult::Ok;
            }

            // Proxy to physical device BAR via pread.
            if let Some(region) = &self.bar_regions[bar as usize] {
                if offset + data.len() as u64 <= region.size {
                    if self
                        .device_file
                        .read_at(data, region.vfio_offset + offset)
                        .is_ok()
                    {
                        return IoResult::Ok;
                    }
                }
                tracelimit::warn_ratelimited!(
                    bar,
                    offset,
                    len = data.len(),
                    pci_id = self.pci_id.as_str(),
                    "VFIO BAR read failed or out of range"
                );
            }
        }
        data.fill(!0);
        IoResult::Ok
    }

    fn mmio_write(&mut self, addr: u64, data: &[u8]) -> IoResult {
        if let Some((bar, offset)) = self.active_bars.find(addr) {
            // Check if this access falls in the MSI-X table or PBA.
            if let Some(emu_offset) = self.msix_emulator_offset(bar, offset) {
                write_msix_emulator(&mut self.msix.as_mut().unwrap().emulator, emu_offset, data);
                return IoResult::Ok;
            }

            // Proxy to physical device BAR via pwrite.
            if let Some(region) = &self.bar_regions[bar as usize] {
                if offset + data.len() as u64 <= region.size {
                    if let Err(e) = self.device_file.write_at(data, region.vfio_offset + offset) {
                        tracelimit::warn_ratelimited!(
                            bar,
                            offset,
                            error = format!("{e:#}").as_str(),
                            pci_id = self.pci_id.as_str(),
                            "VFIO BAR write failed"
                        );
                    }
                    return IoResult::Ok;
                }
            }
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
