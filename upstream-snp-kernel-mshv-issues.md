# Upstream SNP guest kernel issues observed with MSHV

This note records guest-kernel differences observed while bringing up OpenVMM
SEV-SNP support on MSHV. The comparison is between:

- upstream Linux at `~/ai/leafeon/linux-snp-guest`, currently reporting
  `Linux version 7.2.0-rc5-snp-debug`; and
- the ACI 6.6 branch at `~/ai/leafeon/aci-6.6`, commit
  `c2c5adc733fa12d255679d8a246ac06a2eb2e6ed`, currently reporting
  `Linux version 6.6.31-aci-snp`.

Both kernels were built from the same starting configuration. The ACI build
additionally requires `CONFIG_HYPERV=y` because its MSHV-specific code calls
Hyper-V functions that are unavailable when that option is disabled.

## Upstream decompressor GHCB retirement fails

Upstream Linux retires the decompressor GHCB from
`cleanup_exception_handling()`:

```text
arch/x86/boot/compressed/idt_64.c
  cleanup_exception_handling()
    sev_es_shutdown_ghcb()
```

`sev_es_shutdown_ghcb()` clears the decompressor's `boot_ghcb` pointer and
calls `set_page_encrypted()` on the GHCB page. This performs the SNP
shared-to-private page-state change and then executes `PVALIDATE`.

On MSHV:

1. the page-state-change request completes successfully;
2. Linux reaches the private `PVALIDATE`;
3. MSHV reports `UnacceptedGpa` for that GHCB page.

The same upstream guest kernel boots under KVM SNP, and an instrumented
non-GHCB page successfully completes private-to-shared-to-private transitions
under MSHV. The failure is therefore specific to retiring a registered MSHV
GHCB page, not a general failure of SNP page-state transitions.

## ACI disables decompressor GHCB retirement

ACI commit `b96b55f0ae8541f32070104ce03e26aa3a158e29`
(`Fix sev shutdown encrypt ghcb page`) comments out the call:

```c
//sev_es_shutdown_ghcb();
```

This avoids the failing shared-to-private transition. The ACI branch contains
no corresponding explicit E820 or memblock reservation for the abandoned
decompressor GHCB page.

Applying the same one-line workaround to the upstream kernel allows it to
enter the decompressed kernel and initialize ACPI, APIC MMIO, and early memory
management.

## The upstream kernel later reuses the abandoned page

With `sev_es_shutdown_ghcb()` disabled in the upstream kernel, its
decompressor GHCB remains shared at GPA `0x455a000`. The runtime kernel
successfully creates and registers a separate GHCB, then later performs a
private write to `0x455a000`. MSHV reports:

```text
unexpected unaccepted GPA for SNP VP gpa=0x455a000 access=WRITE
```

The decompressor GHCB is part of the decompressor image rather than a
persistent reserved region. Commenting out shutdown leaves it shared but does
not remove it from allocatable RAM, so later reuse is unsafe.

The ACI kernel does not reproduce this fault during the tested boot interval.
It reaches approximately 0.95 seconds of kernel initialization and proceeds
to its MSHV-specific Hyper-V doorbell setup.

No single ACI commit has yet been proven to reserve the abandoned GHCB page.
The branch contains additional startup memory validation and E820 changes,
including commit `23a87ece2436cfd5b1b982b26cc7454a72ccb8e2`, which may change when or
whether the decompressor page is reused. This relationship is currently an
inference, not a confirmed root cause.

## Candidate upstream experiment

A controlled upstream-only workaround is to:

1. keep `sev_es_shutdown_ghcb()` disabled for MSHV bring-up;
2. split the boot E820 RAM entry containing the decompressor GHCB;
3. mark exactly that 4-KiB page reserved before entering the runtime kernel.

This would intentionally leak the page while preserving runtime per-CPU GHCB
registration. It should remain an experiment until the correct MSHV GHCB
retirement semantics are understood.

## ACI-specific protocol requirements

The ACI branch also uses MSHV-specific GHCB operations not required at the
same point by the upstream guest:

- `GHCB_INFO_SPECIAL_DBGPRINT` (`0xf03`) during early boot;
- `SVM_EXITCODE_HV_DOORBELL_PAGE` (`0x80000014`) during interrupt setup.

After OpenVMM accepts the debug-print operation, ACI boots past the abandoned
GHCB failure and stops at the unimplemented doorbell SET request. These are
additional ACI bring-up requirements, not evidence that upstream Linux should
emit the same operations.
