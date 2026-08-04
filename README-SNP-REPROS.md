# SNP Repro Scripts

Run these commands from the repository root.

## KVM

Build OpenVMM and copy it, the initrd, and the run script to the default SNP
host (`cho-snp-ubuntu`):

```bash
SNP_INITRD="$PWD/.packages/underhill-deps-private/x64/initrd" \
    ./copy-snp-artifacts.sh
```

Then boot the SNP guest and run the virtio block and network smoke tests:

```bash
./run-snp-openvmm-repro.sh
```

Use `SNP_HOST` and `SNP_REPRO_HOST` to override the staging and run hosts.

## MSHV

The MSHV script builds and deploys OpenVMM to `wedson-mshv`. Run the ACI SNP
guest with restricted interrupt injection:

```bash
MSHV_SNP_RESTRICTED_INJECTION=1 ./run-mshv-snp-repro.sh
```

To exercise two CPUs, virtio-console input, block I/O, and networking together:

```bash
MSHV_SNP_PROCESSORS=2 \
MSHV_SNP_DEVICE_TEST=both \
MSHV_SNP_CONSOLE=virtio \
MSHV_SNP_RESTRICTED_INJECTION=1 \
    ./run-mshv-snp-repro.sh
```

Set `MSHV_SNP_BUILD_OPENVMM=0` to reuse an existing musl OpenVMM build.
