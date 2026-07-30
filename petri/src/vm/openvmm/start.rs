// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Methods to start a [`PetriVmConfigOpenVmm`] and produce a running [`PetriVmOpenVmm`].

use super::PendingSnpIgvm;
use super::PetriVmConfigOpenVmm;
use super::PetriVmOpenVmm;
use super::PetriVmResourcesOpenVmm;
use crate::OpenvmmLogConfig;
use crate::PetriLogFile;
use crate::PetriVmRuntimeConfig;
use crate::worker::Worker;
use anyhow::Context;
use anyhow::ensure;
use igvmfilegen_config::Config as IgvmConfig;
use igvmfilegen_config::ConfigIsolationType;
use igvmfilegen_config::GuestArch;
use igvmfilegen_config::GuestConfig;
use igvmfilegen_config::Image;
use igvmfilegen_config::LinuxImage;
use igvmfilegen_config::ResourceType;
use igvmfilegen_config::Resources;
use igvmfilegen_config::SecureAvicType;
use igvmfilegen_config::SnpInjectionType;
use mesh_process::Mesh;
use mesh_process::ProcessConfig;
use mesh_worker::WorkerHost;
use openvmm_defs::config::DeviceVtl;
use openvmm_defs::config::IsolationType;
use openvmm_defs::config::LoadMode;
use openvmm_defs::config::Vtl2BaseAddressType;
use openvmm_vm_layout::VmLayoutPlan;
use openvmm_vm_layout::X86ProcessorTopologyPlan;
use pal_async::pipe::PolledPipe;
use pal_async::task::Spawn;
use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_common::tags::OsFlavor;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::ffi::OsString;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use vm_resource::IntoResource;

impl PetriVmConfigOpenVmm {
    async fn run_core(self) -> anyhow::Result<(PetriVmOpenVmm, PetriVmRuntimeConfig)> {
        let Self {
            runtime_config,
            arch,
            host_log_levels,
            mut config,

            mesh,

            mut resources,

            openvmm_log_file,

            memory_backing_file,

            ged,
            framebuffer_view,

            pending_iommu,
            pending_snp_igvm,
        } = self;

        // Resolve deferred IOMMU assignments.
        for (name, iommu_config) in &pending_iommu {
            let rc = config
                .pcie_root_complexes
                .iter_mut()
                .find(|rc| rc.name == *name)
                .with_context(|| format!("IOMMU configured for unknown root complex '{name}'"))?;
            rc.iommu = Some(iommu_config.clone());
        }

        if let Some(request) = pending_snp_igvm {
            generate_snp_igvm(&mut config, &resources, request)
                .await
                .context("generating SNP Linux-direct IGVM")?;
        }

        // TODO: OpenHCL needs virt_whp support
        // TODO: PCAT needs vga device support
        // TODO: arm64 is broken?
        // TODO: VPCI and some PCIe endpoints (NVMe/GDMA) don't support
        // TODO: virtio vsock doesn't support save/restore yet
        // save/restore yet.
        let has_unsupported_pcie_save_restore_device = config
            .pcie_devices
            .iter()
            .any(|device| matches!(device.resource.id(), "nvme" | "gdma"));
        let supports_save_restore = !resources.properties.is_openhcl
            && !resources.properties.is_pcat
            && !matches!(arch, MachineArch::Aarch64)
            && !resources.properties.using_vpci
            && !has_unsupported_pcie_save_restore_device
            && !resources.properties.use_virtio_vsock;

        // Add the GED and VTL 2 settings.
        if let Some(mut ged) = ged {
            ged.vtl2_settings = Some(prost::Message::encode_to_vec(
                runtime_config.vtl2_settings.as_ref().unwrap(),
            ));
            config
                .vmbus_devices
                .push((DeviceVtl::Vtl2, ged.into_resource()));
        }

        async fn generate_snp_igvm(
            config: &mut openvmm_defs::config::Config,
            resources: &PetriVmResourcesOpenVmm,
            request: PendingSnpIgvm,
        ) -> anyhow::Result<()> {
            ensure!(
                resources.properties.use_virtio_vsock && resources.properties.no_vmbus,
                "generated SNP firmware requires virtio-vsock with VMBus disabled"
            );
            ensure!(
                config.hypervisor.with_isolation == Some(IsolationType::Snp),
                "generated SNP firmware requires SNP isolation"
            );
            ensure!(
                !config.hypervisor.with_hv && config.hypervisor.with_vtl2.is_none(),
                "generated SNP firmware does not support Hyper-V enlightenments or VTL2"
            );
            ensure!(
                config.vmbus.is_none()
                    && config.vtl2_vmbus.is_none()
                    && config.vmbus_devices.is_empty(),
                "generated SNP firmware does not support VMBus"
            );
            ensure!(
                config.floppy_disks.is_empty()
                    && config.ide_disks.is_empty()
                    && config.virtio_devices.is_empty()
                    && config.vpci_devices.is_empty(),
                "generated SNP firmware does not support disks or VPCI"
            );
            ensure!(
                config.pcie_switches.is_empty() && config.pcie_generic_initiators.is_empty(),
                "generated SNP firmware does not support PCIe switches or generic initiators"
            );
            ensure!(
                !config.pcie_root_complexes.is_empty(),
                "generated SNP firmware requires a PCIe root complex"
            );
            ensure!(
                config
                    .pcie_root_complexes
                    .iter()
                    .all(|root_complex| root_complex.cxl.is_none()
                        && root_complex.iommu.is_none()
                        && !root_complex.preserve_bars),
                "generated SNP firmware does not support CXL, IOMMUs, or pinned PCIe BARs"
            );
            ensure!(
                config.pcie_devices.len() == 1 && config.pcie_devices[0].resource.id() == "virtio",
                "generated SNP firmware supports only the PCIe virtio-vsock endpoint"
            );
            ensure!(
                config.pcie_root_complexes.iter().any(|root_complex| {
                    root_complex
                        .ports
                        .iter()
                        .any(|port| port.name == config.pcie_devices[0].port_name)
                }),
                "virtio-vsock references a PCIe root port that does not exist"
            );
            ensure!(
                config.framebuffer.is_none() && !config.vtl2_gfx,
                "generated SNP firmware does not support a framebuffer"
            );

            let vm_layout = VmLayoutPlan::from_config(config, 48, None)
                .context("deriving IGVM memory layout")?;
            let processor_topology =
                X86ProcessorTopologyPlan::from_config(&config.processor_topology)
                    .context("deriving IGVM processor topology")?;
            let manifest = IgvmConfig {
                guest_arch: GuestArch::X64,
                guest_configs: vec![GuestConfig {
                    guest_svn: 1,
                    max_vtl: 0,
                    isolation_type: ConfigIsolationType::Snp {
                        shared_gpa_boundary_bits: None,
                        policy: 0x30000,
                        enable_debug: true,
                        injection_type: SnpInjectionType::Normal,
                        secure_avic: SecureAvicType::Disabled,
                    },
                    image: Image::SnpLinuxDirect {
                        linux: LinuxImage {
                            use_initrd: true,
                            command_line: CString::new(request.command_line)
                                .context("Linux command line contains a NUL byte")?,
                        },
                        processor_topology,
                        vm_layout,
                        c_bit_position: None,
                    },
                }],
            };
            let resources_json = Resources::new(std::collections::HashMap::from([
                (ResourceType::LinuxKernel, request.kernel),
                (ResourceType::LinuxInitrd, request.initrd),
                (ResourceType::SnpBootshim, request.snp_bootshim),
            ]))
            .context("building IGVM resource map")?;

            let manifest_path = resources.output_dir.join("generated-snp-manifest.json");
            let resources_path = resources.output_dir.join("generated-snp-resources.json");
            let output_path = resources.output_dir.join("generated-snp.bin");
            fs_err::write(
                &manifest_path,
                serde_json::to_vec_pretty(&manifest).context("serializing IGVM manifest")?,
            )
            .context("writing IGVM manifest")?;
            fs_err::write(
                &resources_path,
                serde_json::to_vec_pretty(&resources_json).context("serializing IGVM resources")?,
            )
            .context("writing IGVM resources")?;

            let mut command = Command::new(&request.igvmfilegen);
            command
                .arg("manifest")
                .arg("--manifest")
                .arg(&manifest_path)
                .arg("--resources")
                .arg(&resources_path)
                .arg("--output")
                .arg(&output_path);
            let tool_result = crate::run_host_cmd(command).await;
            fs_err::write(
                resources.output_dir.join("generated-snp-igvmfilegen.log"),
                match &tool_result {
                    Ok(stdout) => stdout.clone(),
                    Err(error) => format!("{error:#}"),
                },
            )
            .context("writing igvmfilegen output")?;
            tool_result.context("igvmfilegen failed")?;

            config.load_mode = LoadMode::Igvm {
                file: fs_err::File::open(&output_path)
                    .with_context(|| format!("opening generated IGVM {}", output_path.display()))?
                    .into(),
                cmdline: String::new(),
                vtl2_base_address: Vtl2BaseAddressType::File,
                com_serial: None,
            };
            Ok(())
        }

        tracing::debug!(?config, "OpenVMM config");

        let log_env = match host_log_levels {
            None | Some(OpenvmmLogConfig::TestDefault) => BTreeMap::<OsString, OsString>::from([
                // Quiet down `hyper_util`'s connection-pool debug spam that
                // `disk_blob` triggers on every HTTP range request.
                ("OPENVMM_LOG".into(), "debug,hyper_util=info".into()),
                ("OPENVMM_SHOW_SPANS".into(), "true".into()),
            ]),
            Some(OpenvmmLogConfig::BuiltInDefault) => BTreeMap::new(),
            Some(OpenvmmLogConfig::Custom(levels)) => levels
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect::<BTreeMap<OsString, OsString>>(),
        };

        let (host, pid) = Self::openvmm_host(&mut resources, &mesh, openvmm_log_file, log_env)
            .await
            .context("failed to create host process")?;
        // If a memory backing file was requested, open/create it and size
        // it to match the configured guest RAM.
        let shared_memory = memory_backing_file
            .as_ref()
            .map(|mem_path| {
                let total_mem_size: u64 = config
                    .numa
                    .nodes
                    .iter()
                    .filter_map(|n| n.mem.as_ref())
                    .map(|m| m.mem_size)
                    .sum();
                openvmm_helpers::shared_memory::open_memory_backing_file(mem_path, total_mem_size)
            })
            .transpose()?;

        let (worker, halt_notif) = Worker::launch(&host, config, shared_memory)
            .await
            .context("failed to launch vm worker")?;

        let worker = Arc::new(worker);

        let is_minimal = resources.properties.minimal_mode;

        // Resolve the TCP pipette port now, while the VM is starting.
        // Consomme binds the port during launch, so the oneshot should
        // be ready.  Caching the resolved port here lets wait_for_agent
        // reconnect after a reset without needing the oneshot again.
        let tcp_pipette_port = match resources.tcp_pipette_port.take() {
            Some(recv) => Some(
                recv.await
                    .context("failed to receive TCP pipette port from consomme")?,
            ),
            None => None,
        };

        let mut vm = PetriVmOpenVmm::new(
            super::runtime::PetriVmInner {
                resources,
                mesh,
                worker,
                framebuffer_view,
                cidata_mounted: false,
                tcp_pipette_port,
                pid,
            },
            halt_notif,
        );

        tracing::info!("Resuming VM");
        vm.resume().await?;

        // Run basic save/restore test if it is supported
        if supports_save_restore && !is_minimal {
            tracing::info!("Testing save/restore");
            vm.verify_save_restore().await?;
        }

        tracing::info!("VM ready");
        Ok((vm, runtime_config))
    }

    /// Run the VM, configuring pipette to automatically start if it is
    /// included in the config
    pub async fn run(mut self) -> anyhow::Result<(PetriVmOpenVmm, PetriVmRuntimeConfig)> {
        // Set up the IMC hive for Windows guests that use pipette in VTL0.
        // Skip when VMBus is disabled — the no-vmbus prepped image has
        // pipette pre-configured via offline registry injection.
        if self.resources.properties.using_vtl0_pipette
            && matches!(self.resources.properties.os_flavor, OsFlavor::Windows)
            && !self.resources.properties.is_isolated
            && !self.resources.properties.no_vmbus
        {
            let mut imc_hive_file = tempfile::tempfile().context("failed to create temp file")?;
            imc_hive_file
                .write_all(include_bytes!("../../../guest-bootstrap/imc.hiv"))
                .context("failed to write imc hive")?;

            self.config.vmbus_devices.push((
                DeviceVtl::Vtl0,
                vmbfs_resources::VmbfsImcDeviceHandle {
                    file: imc_hive_file,
                }
                .into_resource(),
            ));
        }

        // On non-pipette-as-init Linux direct, launch pipette via the serial
        // agent. (When pipette is PID 1, it auto-starts on boot and the
        // serial agent is not present.)
        let launch_via_serial = self.resources.linux_direct_serial_agent.is_some()
            && self.resources.properties.using_vtl0_pipette;

        // Start the VM.
        let (mut vm, config) = self.run_core().await?;

        if launch_via_serial {
            vm.launch_linux_direct_pipette().await?;
        }

        Ok((vm, config))
    }

    async fn openvmm_host(
        resources: &mut PetriVmResourcesOpenVmm,
        mesh: &Mesh,
        log_file: PetriLogFile,
        vmm_env: BTreeMap<OsString, OsString>,
    ) -> anyhow::Result<(WorkerHost, i32)> {
        // Copy the child's stderr to this process's, since internally this is
        // wrapped by the test harness.
        let (stderr_read, stderr_write) = pal::pipe_pair()?;
        let task = resources.driver.spawn(
            "serial log",
            crate::log_task(
                log_file,
                PolledPipe::new(&resources.driver, stderr_read)
                    .context("failed to create polled pipe")?,
                "openvmm stderr",
            ),
        );
        resources.log_stream_tasks.push(task);

        let (host, runner) = mesh_worker::worker_host();
        let pid = mesh
            .launch_host(
                ProcessConfig::new("vmm")
                    .process_name(&resources.openvmm_path)
                    .stderr(Some(stderr_write))
                    .env(vmm_env),
                openvmm_defs::entrypoint::MeshHostParams { runner },
            )
            .await?;
        Ok((host, pid))
    }
}
