This folder contains manifest recipes for building IGVM files. The build system
normally creates the resource file that supplies each recipe's binary inputs.

## SNP Linux-direct profile

`snp-linux-direct.json` is a bring-up profile with these assumptions:

- x64 and one VTL0 SEV-SNP guest that boots Linux directly
- a serializable processor-topology plan; the default profile uses one virtual
  processor and `snp-linux-direct-multi-vp.json` uses two
- 160 MiB of contiguous RAM (40,960 4-KiB pages)
- COM1 serial ACPI and an optional PCIe root-complex layout; the checked-in
  profiles do not add PCIe
- no shared GPA boundary, normal interrupt injection, and secure AVIC disabled
- base SNP policy `0x30000`; `enable_debug` adds the debug bit to produce the
  current debug-capable policy `0xb0000`
- an initrd and the kernel command line
  `console=ttyS0 earlyprintk=serial earlycon panic=-1`
- SNP C-bit position 51 for reproducible checked-in profiles; omitting
  `c_bit_position` makes `igvmfilegen` derive it from host SEV-SNP CPUID

The normal-injection output is a shared artifact: the same binary is intended
to boot on KVM and MSHV. Its `SnpVpContext` uses the SNP initial-VMSA GPA
`0xffff_ffff_f000`. KVM synthesizes its measured VMSA at that GPA, while MSHV
maps and imports the file-provided VMSA there. Both backends submit the policy
and SNP ID block encoded in the file.

MSHV currently supports only the one-processor profile. The multi-processor
profile remains available for KVM. The
`snp-linux-direct-restricted.json` profile uses the same IGVM encoding with
restricted interrupt injection and is intended only for MSHV bring-up.

The image contains a small measured bootshim. Only pages containing the kernel,
initrd, boot metadata, SNP special pages, bootshim, or bootshim parameters are
included as IGVM `PageData`. After SNP launch, the bootshim accepts the
remaining private RAM with `PVALIDATE` and then enters Linux. This avoids
loading and measuring every configured RAM page, but still accepts all RAM
before Linux starts.

Petri uses the same schema to generate a test-local IGVM after all OpenVMM
backend modifiers have been applied. The final OpenVMM CPU, RAM, chipset, and
PCIe configuration is converted into the shared layout plan, so the ECAM and
MMIO apertures baked into measured ACPI match the root complex OpenVMM
instantiates. Generated manifests, maps, measurement metadata, and IGVM files
remain in the individual test output directory.

The generated SNP profile currently supports one contiguous RAM range starting
at GPA 0 and PCIe root complexes without switches, CXL, IOMMUs, pinned BARs, or
generic initiators. VTL2, VMBus, framebuffer, virtio-mmio, disks, and VPCI are
rejected. Petri's generated boot configuration uses a PCIe virtio-vsock
endpoint for pipette.

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
repo=/absolute/path/to/openvmm
cargo run -p igvmfilegen -- manifest \
  --manifest "$repo/vm/loader/manifests/snp-linux-direct.json" \
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

Build the MSHV restricted-injection variant by substituting
`vm/loader/manifests/snp-linux-direct-restricted.json` and a distinct build
label.

The standard outputs are:

- `snp-linux-direct.bin`
- `snp-linux-direct.bin.map`
- `snp-linux-direct-snp.json`
