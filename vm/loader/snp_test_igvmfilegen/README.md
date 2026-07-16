# SNP test IGVM generator

`snp_test_igvmfilegen` creates a deliberately fixed SEV-SNP IGVM for
OpenVMM's SNP IGVM-loader bring-up.

```bash
cargo run -p snp_test_igvmfilegen -- \
  --kernel /path/to/vmlinux-or-bzImage \
  --initrd /path/to/initrd \
  --output /tmp/snp-test.igvm
```

The initrd is optional. The generated image directly boots Linux and contains
no OpenHCL bootshim or sidecar kernel.

The image hardcodes:

- 160 MiB contiguous RAM
- one virtual processor
- COM1-only serial ACPI
- no VMBus, PCIe, disks, IOMMU, or PSP
- `console=ttyS0 earlyprintk=serial earlycon panic=-1`
- the SNP C-bit at physical-address bit 51

Bit 51 is a test-host assumption, not a portable SNP property. A future loader
must reject this image on a host whose CPUID reports a different C-bit
position.

Every page of the 160 MiB RAM layout is emitted as a measured SNP `NORMAL`
page, including pages whose contents are zero. A loader must not replace those
directives with SNP `ZERO` launch updates because that would change the signed
launch digest. The VMSA directive is emitted last at KVM's fixed
`0xFFFFFFFFF000` GPA so its measurement order matches KVM launch finish.
Its reset state also includes the CR0.ET and CR4.MCE bits that KVM's SVM
backend forces before measuring the VMSA.

The current direct-Linux SNP path completes missing RAM imports before entering
`virt_kvm`; `virt_kvm` no longer synthesizes missing RAM. An IGVM loader must
likewise provide every page described by this file, but must bypass the
direct-boot optimization that converts zero-valued `NORMAL` pages to SNP
`ZERO` updates.

The tool writes:

- the requested `.igvm`
- `<output>.map`
- `<stem>-snp.json` with the launch digest
- `<stem>.openvmm.json` with the expected OpenVMM launch shape

The launch contract is documentation for the loader implementation and is not
automatically consumed by OpenVMM.
