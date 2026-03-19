// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenHCL ASAN (AddressSanitizer) stress tests.
//!
//! These tests run existing OpenHCL workloads against an ASAN-instrumented
//! IGVM to detect memory corruption bugs (use-after-free, buffer overflows,
//! etc.). They exercise memory-heavy code paths: VM boot (DMA, memory
//! mapping), and VTL2 initialization.

use petri::PetriVmBuilder;
use petri::openvmm::OpenVmmPetriBackend;
use petri_artifacts_common::tags::IsOpenhclIgvm;
use petri_artifacts_vmm_test::artifacts::openhcl_igvm::LATEST_ASAN_X64;
use vmm_test_macros::openvmm_test;

/// Boot an OpenHCL UEFI VM with ASAN-instrumented OpenHCL.
///
/// Exercises the full VTL2 initialization path, UEFI guest handoff, and
/// guest OS boot — all with ASAN memory checking enabled. This catches
/// corruption in the hot memory-mapping and DMA setup paths.
#[openvmm_test(openhcl_uefi_x64(vhd(ubuntu_2504_server_x64))[LATEST_ASAN_X64])]
async fn openhcl_asan_boot(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    (asan_igvm,): (petri::ResolvedArtifact<impl IsOpenhclIgvm>,),
) -> anyhow::Result<()> {
    let (vm, agent) = config.with_custom_openhcl(asan_igvm).run().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Boot an OpenHCL Linux-direct VM with ASAN-instrumented OpenHCL.
///
/// Exercises the VTL2 initialization and Linux direct-boot path without
/// UEFI complexity — a lighter-weight but still memory-intensive workload.
#[openvmm_test(openhcl_linux_direct_x64 [LATEST_ASAN_X64])]
async fn openhcl_asan_linux_direct_boot(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
    (asan_igvm,): (petri::ResolvedArtifact<impl IsOpenhclIgvm>,),
) -> anyhow::Result<()> {
    let (vm, agent) = config.with_custom_openhcl(asan_igvm).run().await?;
    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}
