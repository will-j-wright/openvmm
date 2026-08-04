# MSHV SNP Investigation Notes

## Current working baseline

OpenVMM can direct-boot the ACI Linux 6.6 kernel as a one-processor SEV-SNP
guest on MSHV. The known-working configuration uses:

- the ACI `nord_defconfig` kernel;
- 160 MB of guest RAM;
- restricted interrupt injection;
- the MSHV SNP GHCB handlers currently implemented in `virt_mshv`;
- the temporary supervisor-XSTATE CPUID compatibility mask.

The current ACI boot also emits a nonfatal invalid-physical-address warning
from `boot_params_ksysfs_init()`. Reaching the initrd shell is the current
bring-up criterion, not evidence of a warning-free guest boot.

`run-mshv-snp-repro.sh` builds a static-musl OpenVMM, deploys the artifacts to
`wedson-mshv`, captures the complete console, and validates either one-CPU or
multi-CPU Linux startup.

## SNP AP creation

The GHCB AP-create path is implemented and is worth retaining:

1. advertise `GHCB_HYP_FEATURE_SEV_SNP_AP_CREATION`;
2. validate the GHCB request fields;
3. map the guest APIC ID to an existing OpenVMM VP index;
4. validate the guest-provided VMSA GPA;
5. call `MSHV_SEV_SNP_AP_CREATE`;
6. return success or an in-band GHCB error.

Only ordinary `CREATE` is implemented. `CREATE_ON_INIT` and `DESTROY` currently
return an in-band unsupported-input error with TODOs; they must be implemented
before CPU hotplug, kexec, or a complete AP lifecycle is claimed.

Current SNP SMP support also assumes the guest APIC ID equals the MSHV VP
index. Non-identity APIC topologies require additional VP APIC-ID programming
or explicit rejection before they can be supported safely.

The target MSHV kernel requires the VP to exist before this ioctl. OpenVMM
already creates and binds every configured VP before firmware loading and SNP
page import. The kernel ioctl synchronously sets the target VP's `SevControl`
register to the supplied VMSA page and clears its internal startup-suspend
state.

ACI instrumentation confirmed that VP1 was started with:

```text
APIC ID:       1
VMSA GPA:      0x517000
entry address: 0x9a050
```

With the cluster-IPI recommendation temporarily hidden, VP1 reached
`hv_common_cpu_init()`, reported VP index 1, and Linux reported two active
processors. This demonstrates that the AP-create ioctl bound the supplied VMSA,
the APIC-ID mapping was correct, and VP1 executed from that state.

Full SMP validation is deferred until testing the guest kernel used by Cloud
Hypervisor. The ACI kernel is not the guest used by Cloud Hypervisor's MSHV SNP
configuration.

## ACI hypercall-page finding

The ACI kernel registers an executable Hyper-V hypercall-page overlay at GPA
`0x4ee000`. With its normal Hyper-V enlightenment hints, Linux selects
hypercall-based IPIs. VP1 then receives an MSHV `UnacceptedGpa` execute exit at
that exact GPA during startup.

The following experiments did not resolve the fault:

- adding the `access_vp_regs` synthetic capability;
- explicitly transitioning the hypercall page's backing page to shared memory.

Temporarily clearing `HV_X64_CLUSTER_IPI_RECOMMENDED` avoids the overlay during
AP startup and brings VP1 online, but the ACI guest later hangs after launching
`/init`. This workaround is not retained. Cloud Hypervisor leaves the
cluster-IPI recommendation enabled and contains no explicit hypercall-overlay
acceptance or visibility handling.

The conclusion is kernel-specific: the AP protocol is working, while the ACI
kernel and this MSHV environment disagree about using the Hyper-V hypercall
overlay from an SNP AP. Do not generalize this result to the Cloud Hypervisor
guest kernel.

## Discarded diagnostics and experiments

The following are investigation-only and should not be committed:

- ACI prints for GHCB, doorbell, VP-assist, hypercall-page, AP VMSA, and CPUID
  addresses;
- clearing the cluster-IPI recommendation;
- adding `access_vp_regs` solely as an overlay experiment;
- explicitly sharing the hypercall backing page.

The incremental ACI `build-snp-guest.sh` helper remains useful for subsequent
one-processor device testing.

## Next work

### ACI one-processor PCIe virtio

Keep the current ACI guest at one processor and add the PCIe virtio devices
already exercised by the KVM SNP repro:

- `virtio-console` as new coverage;
- memory-backed `virtio-blk`, including write/read verification;
- `virtio-net` with the consomme backend, including enumeration, link setup,
  and gateway connectivity.

Extend the remote repro to run deterministic guest smoke markers for these
devices and add focused tests for the configuration and success detection.

### Cloud Hypervisor guest kernel

After the ACI device work, obtain the external IGVM artifact used by Cloud
Hypervisor's MSHV confidential tests and identify or extract its guest kernel.
Current OpenVMM SNP support is direct-Linux-only, so boot the extracted kernel
directly first. Treat standard injection as a diagnostic configuration until
the artifact's VMSA `sev_features` is inspected. Compare:

- Hyper-V CPUID leaves and synthetic features;
- SNP CPUID and XSTATE exposure;
- GHCB AP-creation behavior;
- hypercall-page and VP-assist behavior;
- runtime GPA visibility changes.

Comparing imported IGVM page types requires a separate OpenVMM SNP IGVM
milestone and is not part of the immediate direct-kernel experiment.

Resume SMP/AP validation against that kernel rather than adding more ACI-only
workarounds.
