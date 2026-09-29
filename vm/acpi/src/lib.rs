// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate for dynamically creating ACPI tables.
//!
//! [`snp`] validates the hardware topology for the fixed x86 SNP Linux base
//! tables.

#![no_std]
#![expect(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod aml;
pub mod builder;
pub mod cedt;
pub mod dsdt;
pub mod snp;
pub mod ssdt;
