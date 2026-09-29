// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate for dynamically creating ACPI tables.
//!
//! [`snp`] constructs the fixed x86 SNP Linux base tables from a bounded,
//! validated topology.

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
