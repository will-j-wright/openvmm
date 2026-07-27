This folder contains manifest recipes for building IGVM files. The build system
normally creates the resource file that supplies each recipe's binary inputs.

## SNP Linux-direct profile

`snp-linux-direct.json` is a bring-up profile with these assumptions:

- x64 and one VTL0 SEV-SNP guest that boots Linux directly
- one virtual processor; `snp-linux-direct-multi-vp.json` uses two
- 160 MiB of contiguous RAM (40,960 4-KiB pages)
- COM1-only serial ACPI, with no VMBus, PCIe, disks, IOMMU, or PSP
- no shared GPA boundary, normal interrupt injection, and secure AVIC disabled
- base SNP policy `0x30000`; `enable_debug` adds the debug bit to produce the
  current debug-capable policy `0xb0000`
- an initrd and the kernel command line
  `console=ttyS0 earlyprintk=serial earlycon panic=-1`
- SNP C-bit position 51, which is a test-host assumption rather than a portable
  SNP property

The image contains a small measured bootshim. Only pages containing the kernel,
initrd, boot metadata, SNP special pages, bootshim, or bootshim parameters are
included as IGVM `PageData`. After SNP launch, the bootshim accepts the remaining
private RAM with `PVALIDATE` and then enters Linux. This avoids loading and
measuring every configured RAM page, but still accepts all RAM before Linux
starts.

To build it manually, create a resources file containing absolute paths:

```json
{
    "resources": {
        "linux_kernel": "/absolute/path/to/vmlinux-or-bzImage",
        "linux_initrd": "/absolute/path/to/initrd",
        "snp_bootshim": "/absolute/path/to/snp_bootshim"
    }
}
```

Build the bootshim first:

```bash
MINIMAL_RT_BUILD=1 cargo build \
  --profile boot-dev \
  --target x86_64-unknown-none \
  -p snp_bootshim
```

Then run:

```bash
cargo run -p igvmfilegen -- manifest \
  --manifest /absolute/path/to/openvmm/vm/loader/manifests/snp-linux-direct.json \
  --resources /absolute/path/to/snp-linux-direct-resources.json \
  --output /absolute/path/to/snp-linux-direct.bin
```

Flowey can build the bootshim and populate the resource map automatically:

```bash
cargo xflowey build-igvm x64-test-linux-direct \
  --override-manifest \
  vm/loader/manifests/snp-linux-direct.json \
  --build-label snp-linux-direct
```

The standard outputs are:

- `snp-linux-direct.bin`
- `snp-linux-direct.bin.map`
- `snp-linux-direct-snp.json`
