// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate for dynamically creating ACPI tables.
//!
//! The core builders use `no_std` with `alloc`. The optional `cxl` feature adds
//! CEDT support and its hosted device-definition dependency.

#![no_std]
#![expect(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod aml;
pub mod builder;
#[cfg(feature = "cxl")]
pub mod cedt;
pub mod dsdt;
pub mod ssdt;
