// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generates a fixed-shape SEV-SNP IGVM for OpenVMM loader bring-up.

#![forbid(unsafe_code)]

crypto::ensure_single_backend!();

use anyhow::Context;
use clap::Parser;
use snp_test_igvmfilegen::GenerateOptions;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "snp_test_igvmfilegen",
    about = "Generate a fixed 160 MiB, one-VP, direct-Linux SEV-SNP test IGVM"
)]
struct Options {
    /// Linux kernel image (ELF or bzImage).
    #[arg(long)]
    kernel: PathBuf,

    /// Optional initrd image.
    #[arg(long)]
    initrd: Option<PathBuf>,

    /// Output IGVM path.
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let artifacts = snp_test_igvmfilegen::generate(GenerateOptions {
        kernel: options.kernel,
        initrd: options.initrd,
        output: options.output,
    })
    .context("generating SNP test IGVM")?;

    println!("IGVM: {}", artifacts.igvm.display());
    println!("Map: {}", artifacts.map.display());
    println!("Measurement: {}", artifacts.measurement.display());
    println!("OpenVMM contract: {}", artifacts.openvmm_contract.display());
    Ok(())
}
