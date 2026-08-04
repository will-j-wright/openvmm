# MSHV SNP ACI IOAPIC Investigation

## Status

The ACI 6.6 guest reaches its initrd shell under MSHV SNP when:

- OpenVMM exposes the non-paravisor Hyper-V SNP isolation CPUID contract;
- the direct Linux loader follows the ACI/IGVM boot layout;
- ACI keeps IOAPIC support enabled instead of forcing legacy PIC/LINT0
  delivery.

The successful one-processor run is:

```text
target/mshv-snp/20260731T015444Z-qvrlrxln-39ed0ccb/
```

The same bounded-import layout also boots with 2 GB of RAM:

```text
target/mshv-snp/20260731T025025Z-qvrlrxln-4d24b62f/
```

Relevant console output:

```text
Hyper-V: Isolation Config: Group A 0x0, Group B 0x2
IOAPIC[0]: apic_id 0, version 17, address 0xfec00000, GSI 0-23
ACPI: Using IOAPIC for interrupt routing
No root device specified. Dropping to a shell.
~ #
```

## Temporary ACI kernel change

The ACI checkout is:

```text
~/ai/leafeon/aci-6.6
```

The only required source experiment is in:

```text
arch/x86/hyperv/ivm.c
```

In `hv_sev_init_mem_and_cpu()`, replace:

```c
disable_ioapic_support();
```

with:

```c
/* TEMPORARY: Keep IOAPIC enabled while testing OpenVMM PCI/legacy IRQ routing. */
```

This patch is intentionally uncommitted in the ACI repository.

Rebuild with:

```bash
cd ~/ai/leafeon/aci-6.6
SNP_GUEST_OUT="$PWD/out/snp-nord" \
SNP_GUEST_BASE_CONFIG="$PWD/arch/x86/configs/nord_defconfig" \
./build-snp-guest.sh build
```

Run with:

```bash
cd ~/ai/leafeon/openvmm
MSHV_SNP_PROCESSORS=1 ./run-mshv-snp-repro.sh
```

## Why the patch is needed

When ACI sees the correct Hyper-V isolation CPUID values, it enters its
enlightened SNP boot path:

```text
0x40000003:EBX[22] = 1
0x4000000c:EAX = 0
0x4000000c:EBX = 2
```

`hv_sev_init_mem_and_cpu()` then calls `disable_ioapic_support()`. The guest
uses the emulated legacy PIC and expects its aggregate output to be delivered
through LAPIC LINT0 as an ExtINT.

OpenVMM's MSHV backend does not currently have a usable encrypted-VP ExtINT
injection path. The following approaches were tested and rejected by MSHV:

1. `LOCALINT0` through `request_virtual_interrupt()` returned
   `InvalidParameter`.
2. Requesting interruption-deliverable notifications through the partition
   hypercall returned `InvalidParameter`.
3. Setting the VP `DeliverabilityNotifications` register failed.
4. Acknowledging the PIC and setting VP `PendingEvent0` to an ExtINT event
   failed.

Without working ExtINT delivery, Linux reaches `/init`, but ttyS0 output does
not progress to the shell. A diagnostic initrd proved that `/init` itself was
running and successfully mounted devtmpfs, sysfs, proc, and devpts; only the
interrupt-driven serial output path was unavailable.

Keeping IOAPIC enabled allows OpenVMM to route legacy device IRQs through its
IOAPIC/MSI machinery, which MSHV already supports. Serial IRQ4 then works and
the shell becomes visible.

## Relationship to Cloud Hypervisor

Cloud Hypervisor does not emulate a legacy PIC. Its legacy devices feed a
userspace IOAPIC, which translates interrupts into MSI routes and irqfd/MSHV
virtual interrupts. It therefore does not require a PIC-to-LINT0 fallback.

The temporary ACI patch makes the guest interrupt model closer to Cloud
Hypervisor's model and is also a better fit for planned PCIe virtio devices,
which should use MSI/MSI-X rather than legacy INTx.

## OpenVMM baseline

The OpenVMM baseline contains:

- explicit Hyper-V isolation CPUID overrides, with a TODO because Cloud
  Hypervisor has no equivalent override and its MSHV environment has not been
  confirmed;
- an ACI/IGVM-compatible direct Linux layout:
  - bzImage at its preferred address;
  - fixed SNP metadata pages around `0x800000`;
  - VP count and IGVM-style memory map at `0x802000`;
  - bounded initial page imports instead of accepting all guest RAM;
- unit tests for the new layout and parameter page.

The failed PIC injection experiments have been removed from the working copy.
`pulse_lint()` remains an ignored, rate-limited TODO.

## Remaining work

1. Decide whether the IOAPIC behavior should remain an ACI kernel patch or be
   exposed as a guest/kernel configuration.
2. Test two processors. With isolation CPUID enabled, ACI uses
   `HvCallStartVirtualProcessor`; OpenVMM does not yet implement that hypercall.
3. Enable ACI kernel PCI and virtio PCI options, then add one-processor PCIe
   virtio-console, virtio-blk, and virtio-net smoke tests.
