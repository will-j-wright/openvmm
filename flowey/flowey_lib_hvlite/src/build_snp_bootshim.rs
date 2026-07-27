// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build the SNP Linux-direct bootshim.

use crate::run_cargo_build::BuildProfile;
use flowey::node::prelude::*;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub struct SnpBootshimOutput {
    #[serde(rename = "snp_bootshim")]
    pub bin: PathBuf,
    #[serde(rename = "snp_bootshim.dbg")]
    pub dbg: PathBuf,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SnpBootshimBuildProfile {
    Debug,
    Release,
}

flowey_request! {
    pub struct Request {
        pub profile: SnpBootshimBuildProfile,
        pub snp_bootshim: WriteVar<SnpBootshimOutput>,
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::run_cargo_build::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let requests =
            requests
                .into_iter()
                .fold(BTreeMap::<_, Vec<_>>::new(), |mut requests, request| {
                    requests
                        .entry(request.profile)
                        .or_default()
                        .push(request.snp_bootshim);
                    requests
                });

        for (profile, outputs) in requests {
            let target = target_lexicon::Triple {
                architecture: target_lexicon::Architecture::X86_64,
                operating_system: target_lexicon::OperatingSystem::None_,
                environment: target_lexicon::Environment::Unknown,
                vendor: target_lexicon::Vendor::Custom(target_lexicon::CustomVendor::Static(
                    "minimal_rt",
                )),
                binary_format: target_lexicon::BinaryFormat::Unknown,
            };
            let profile = match profile {
                SnpBootshimBuildProfile::Debug => BuildProfile::BootDev,
                SnpBootshimBuildProfile::Release => BuildProfile::BootRelease,
            };
            let output = ctx.reqv(|v| crate::run_cargo_build::Request {
                crate_name: "snp_bootshim".into(),
                out_name: "snp_bootshim".into(),
                crate_type: flowey_lib_common::run_cargo_build::CargoCrateType::Bin,
                profile,
                features: Default::default(),
                target,
                no_split_dbg_info: false,
                extra_env: Some(ReadVar::from_static(
                    [
                        ("RUSTC_BOOTSTRAP".to_string(), "1".to_string()),
                        ("CC_FORCE_DISABLE".to_string(), "1".to_string()),
                    ]
                    .into_iter()
                    .collect(),
                )),
                pre_build_deps: Vec::new(),
                output: v,
            });

            ctx.emit_minor_rust_step("report built snp_bootshim", |ctx| {
                let outputs = outputs.claim(ctx);
                let output = output.claim(ctx);
                move |rt| {
                    let output = match rt.read(output) {
                        crate::run_cargo_build::CargoBuildOutput::ElfBin { bin, dbg } => {
                            SnpBootshimOutput {
                                bin,
                                dbg: dbg.unwrap(),
                            }
                        }
                        _ => unreachable!(),
                    };
                    for variable in outputs {
                        rt.write(variable, &output);
                    }
                }
            });
        }

        Ok(())
    }
}
