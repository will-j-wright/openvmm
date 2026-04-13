// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource resolver for VFIO-assigned PCI devices.

use crate::VfioAssignedPciDevice;
use crate::VfioAssignedPciDeviceConfig;
use crate::VfioBarInfo;
use anyhow::Context as _;
use async_trait::async_trait;
use pci_resources::ResolvePciDeviceHandleParams;
use pci_resources::ResolvedPciDevice;
use vfio_assigned_device_resources::VfioDeviceHandle;
use vm_resource::AsyncResolveResource;
use vm_resource::ResourceResolver;
use vm_resource::declare_static_async_resolver;
use vm_resource::kind::PciDeviceHandleKind;

/// Resource resolver for [`VfioDeviceHandle`].
pub struct VfioDeviceResolver;

declare_static_async_resolver! {
    VfioDeviceResolver,
    (PciDeviceHandleKind, VfioDeviceHandle),
}

#[async_trait]
impl AsyncResolveResource<PciDeviceHandleKind, VfioDeviceHandle> for VfioDeviceResolver {
    type Output = ResolvedPciDevice;
    type Error = anyhow::Error;

    async fn resolve(
        &self,
        _resolver: &ResourceResolver,
        resource: VfioDeviceHandle,
        input: ResolvePciDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        use std::path::Path;

        let pci_id = &resource.pci_id;
        let sysfs_path = Path::new("/sys/bus/pci/devices").join(pci_id);

        tracing::info!(pci_id, "opening VFIO device");

        let container = vfio_sys::Container::new().context("failed to open VFIO container")?;
        let group_id = vfio_sys::Group::find_group_for_device(&sysfs_path)
            .with_context(|| format!("failed to find IOMMU group for {pci_id}"))?;
        let group = vfio_sys::Group::open(group_id)
            .with_context(|| format!("failed to open VFIO group {group_id}"))?;
        group
            .set_container(&container)
            .context("failed to set VFIO container")?;
        container
            .set_iommu(vfio_sys::IommuType::Type1v2)
            .context("failed to set VFIO IOMMU type to Type1v2 (IOMMU required)")?;

        // Map guest RAM into the IOMMU for device DMA access. Each
        // RAM range is identity-mapped (IOVA == GPA) so that device
        // DMA addresses match guest physical addresses.
        let mem_layout = input
            .mem_layout
            .context("VFIO requires mem_layout in resolve params")?;

        let (base_va, va_size) = input
            .guest_memory
            .full_mapping()
            .context("VFIO DMA mapping requires linearly mapped guest memory")?;

        for ram_range in mem_layout.ram() {
            let gpa_start = ram_range.range.start();
            let size = ram_range.range.len();
            anyhow::ensure!(
                gpa_start + size <= va_size as u64,
                "RAM range {:#x}..{:#x} exceeds guest memory mapping size {:#x}",
                gpa_start,
                gpa_start + size,
                va_size
            );
            let vaddr = base_va as u64 + gpa_start;
            container.map_dma(gpa_start, vaddr, size).with_context(|| {
                format!(
                    "failed to map DMA for RAM range {:#x}..{:#x}",
                    gpa_start,
                    gpa_start + size
                )
            })?;
            tracing::debug!(gpa_start, size, vaddr, "mapped guest RAM for VFIO DMA");
        }

        let driver = input.driver_source.simple();
        let device = group
            .open_device(pci_id, &driver)
            .await
            .with_context(|| format!("failed to open VFIO device {pci_id}"))?;

        let config_info = device
            .region_info(vfio_bindings::bindings::vfio::VFIO_PCI_CONFIG_REGION_INDEX)
            .context("failed to get VFIO config region info")?;

        // Query VFIO region info for each BAR (indices 0-5).
        let mut bar_info: [Option<VfioBarInfo>; 6] = [None; 6];
        for i in 0u32..6 {
            if let Ok(info) = device.region_info(i) {
                if info.size > 0 {
                    bar_info[i as usize] = Some(VfioBarInfo {
                        vfio_offset: info.offset,
                        size: info.size,
                    });
                }
            }
        }

        let irqfd = input
            .irqfd
            .context("partition does not support irqfd (required for VFIO)")?;

        // Register MMIO regions for each BAR with the chipset.
        let bar_mmio_controls: Vec<_> = bar_info
            .iter()
            .enumerate()
            .map(|(i, info)| {
                let size = info.map_or(0, |bi| bi.size);
                input.register_mmio.new_io_region(&format!("bar{i}"), size)
            })
            .collect();

        let device = VfioAssignedPciDevice::new(VfioAssignedPciDeviceConfig {
            pci_id: pci_id.clone(),
            vfio_device: device,
            config_offset: config_info.offset,
            config_size: config_info.size,
            msi_target: input.msi_target.clone(),
            bar_info,
            irqfd,
            bar_mmio_controls,
            vfio_container: container,
            vfio_group: group,
        })?;

        Ok(device.into())
    }
}
