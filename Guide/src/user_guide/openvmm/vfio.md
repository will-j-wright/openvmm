# VFIO Device Assignment

This page explains how to assign a physical PCI device to an OpenVMM guest using Linux VFIO.

VFIO device assignment lets a guest VM directly access a physical PCI device (such as an NVMe controller or GPU). The guest sees the real device in its PCI bus and can interact with its config space.

```admonish warning
VFIO device assignment is experimental. PCI config space, BAR MMIO passthrough, and MSI-X interrupts (via irqfd) are functional. DMA (IOMMU mapping of guest memory) is not yet implemented — devices that require DMA will not work correctly.
```

## Overview

OpenVMM running on a Linux host can assign physical PCI devices to guest VMs using VFIO. The device is bound to the `vfio-pci` kernel driver, then OpenVMM opens it via VFIO and presents it to the guest as a PCIe endpoint.

```text
Linux Host
└── OpenVMM
    └── Guest VM
        └── sees physical PCI device via ECAM
```

## Prerequisites

- A Linux host with IOMMU support enabled (Intel VT-d or AMD-Vi)
- A PCI device available for passthrough
- The `vfio-pci` kernel module loaded
- The `vfio_iommu_type1` kernel module loaded

## Step 1: Identify the device

Find the PCI device you want to assign:

```bash
lspci
```

Look for the device's BDF (bus:device.function) address, for example `3f7a:00:00.0`.

## Step 2: Enable unsafe interrupts

Some IOMMU implementations do not support interrupt remapping. If VFIO fails to set up the IOMMU with an "interrupt remapping" error, allow it to proceed without:

```bash
echo 1 | sudo tee /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
```

```admonish note
This flag is required in environments where the IOMMU does not support interrupt remapping (e.g., some nested virtualization setups). The "unsafe" label means a device could theoretically forge interrupt messages. In practice, this is acceptable when the host platform already constrains device behavior.
```

To make this persistent across reboots, add a modprobe config:

```bash
echo "options vfio_iommu_type1 allow_unsafe_interrupts=1" | sudo tee /etc/modprobe.d/vfio.conf
```

## Step 3: Bind the device to vfio-pci

If the device is currently bound to another driver (e.g., `nvme`), unbind it first:

```bash
echo "3f7a:00:00.0" | sudo tee /sys/bus/pci/devices/3f7a:00:00.0/driver/unbind
```

Then bind to `vfio-pci`:

```bash
echo "vfio-pci" | sudo tee /sys/bus/pci/devices/3f7a:00:00.0/driver_override
echo "3f7a:00:00.0" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
```

Verify the binding:

```bash
ls -la /sys/bus/pci/devices/3f7a:00:00.0/driver
# Should show: ... -> ../../../../bus/pci/drivers/vfio-pci
```

```admonish warning
If the device is an NVMe controller backing a mounted filesystem, unbinding it will cause data loss. Make sure you are not using the device before unbinding.
```

## Step 4: Verify VFIO group

Check that a VFIO group device was created:

```bash
ls /dev/vfio/
```

You should see a numbered group (e.g., `/dev/vfio/0`) or a `noiommu-` prefixed group. Either is fine.

## Step 5: Launch OpenVMM with the VFIO device

Use the `--vfio` flag to assign the device to a PCIe root port. You also need to create a PCIe root complex and root port for the device to attach to:

```bash
sudo openvmm \
  --pcie-root-complex rc0 \
  --pcie-root-port rc0:rp0 \
  --vfio rp0:3f7a:00:00.0 \
  --kernel /path/to/vmlinux \
  --initrd /path/to/initrd \
  --cmdline "console=ttyS0" \
  --com1 console \
  --memory 256M \
  --processors 2
```

The `--vfio` syntax is `<port_name>:<pci_bdf>`:

- `rp0` — the name of the PCIe root port to attach the device to (must match a `--pcie-root-port` name)
- `3f7a:00:00.0` — the PCI BDF of the VFIO device on the host

```admonish tip
You can assign multiple devices by adding more root ports and `--vfio` flags:

    --pcie-root-port rc0:rp0 \
    --pcie-root-port rc0:rp1 \
    --vfio rp0:3f7a:00:00.0 \
    --vfio rp1:334c:00:00.0
```

## Step 6: Verify in the guest

If the guest boots with PCI support, the assigned device should be visible:

```bash
lspci
```

The device will appear with its real vendor and device ID from the physical hardware.

## Troubleshooting

### "No such file or directory" for `/dev/vfio/noiommu-*`

The device has a real IOMMU group. Make sure you completed Step 2 (allow unsafe interrupts) and that the device is bound to `vfio-pci`.

### "No interrupt remapping" / ENODEV on IOMMU setup

Run Step 2 to enable `allow_unsafe_interrupts`. This is needed when the platform's IOMMU does not support interrupt remapping.

### "failed to open VFIO device" / permission denied

Run OpenVMM with `sudo`, or add your user to the `vfio` group and set appropriate permissions on `/dev/vfio/` devices.

### Device not visible in guest `lspci`

- Verify the device is bound to `vfio-pci` (Step 3)
- Verify the VFIO group exists in `/dev/vfio/` (Step 4)
- Verify the `--vfio` port name matches a `--pcie-root-port` name
- Check OpenVMM log output for errors during VFIO device initialization

## Current Limitations

- **Config space only** — the guest can enumerate the device and read/write PCI config space, but MMIO BAR access, MSI-X interrupts, and DMA are not yet implemented.
- **No save/restore** — VMs with VFIO devices cannot be saved or migrated.
- **Linux only** — the `--vfio` flag is only available when OpenVMM is built and run on Linux. On Windows, use `--device` with WHP for device assignment.
