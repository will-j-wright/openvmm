#!/bin/bash
# Run the minimal KVM SNP IGVM scenario from copied artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

OPENVMM_BIN="${OPENVMM_BIN:-$SCRIPT_DIR/openvmm}"
IGVM="${SNP_IGVM:-$SCRIPT_DIR/snp-linux-direct.bin}"
# Must match the RAM described by the IGVM.
MEMORY="${SNP_MEMORY:-160MB}"
PROCESSORS="${SNP_PROCESSORS:-1}"
OPENVMM_LOG="${OPENVMM_LOG:-info,virt_kvm=trace,kvm=trace,openvmm_core::worker::dispatch=debug}"
VIRTIO_BLK_SIZE="${SNP_VIRTIO_BLK_SIZE:-64M}"

for file in "$OPENVMM_BIN" "$IGVM"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: missing required artifact: $file" >&2
        exit 1
    fi
done

cmd=(
    env "OPENVMM_LOG=$OPENVMM_LOG" "$OPENVMM_BIN"
    --hypervisor kvm
    --isolation snp
    --igvm "$IGVM"
    --igvm-personality linux-direct
    --com1 console
    --pcie-root-complex rc0,segment=0,start_bus=0,end_bus=255,low_mmio=4M,high_mmio=1G
    --pcie-root-port rc0:blk
    --virtio-blk "mem:$VIRTIO_BLK_SIZE,pcie_port=blk"
    --no-vmbus
    -m "$MEMORY"
    -p "$PROCESSORS"
)

printf 'Running:'
printf ' %q' "${cmd[@]}"
printf '\n'

exec "${cmd[@]}"
