// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SEV-SNP launch support for KVM partitions.
//!
//! The loader writes initial private page contents into the userspace side of
//! guestmemfd-backed slots. This module translates the loader's import types
//! into SNP launch updates, constructs the firmware CPUID page from the BSP's
//! effective KVM CPUID table, validates the initial BSP state, and finalizes
//! the launch context. Runtime shared/private transitions are handled by the
//! memory module rather than the launch path.

use crate::KvmError;
use crate::KvmPartition;
use crate::KvmPartitionInner;
use crate::memory::MemoryError;
use crate::memory::private_memory_range_from_slots;
use std::os::fd::AsFd;
use std::sync::Arc;
use thiserror::Error;
use virt::InitialPageImportType;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

pub(crate) const KVM_SNP_VMSA_GPA: u64 = 0xffff_ffff_f000;

#[derive(Debug, Error)]
pub enum SnpError {
    #[error("SNP isolation is not configured")]
    IsolationNotSupported,
    #[error("failed to open /dev/sev")]
    OpenSev(#[source] std::io::Error),
    #[error("unsupported SNP launch page import type: {0:?}")]
    UnsupportedPageImportType(InitialPageImportType),
    #[error("missing SNP VMSA import")]
    MissingVmsa,
    #[error("multiple SNP VMSA imports")]
    MultipleVmsa,
    #[error("invalid SNP VMSA")]
    InvalidVmsa(#[source] virt::x86::snp::SnpVmsaError),
    #[error("failed to access SNP VMSA memory")]
    VmsaMemory(#[source] guestmem::GuestMemoryError),
    #[error("invalid SNP launch range")]
    InvalidLaunchRange,
    #[error("too many CPUID entries for SNP launch page: {0}")]
    TooManyCpuidEntries(usize),
    #[error("SNP launch is already in progress")]
    LaunchInProgress,
    #[error("SNP launch is already complete")]
    LaunchAlreadyFinished,
    #[error("SNP launch previously failed")]
    LaunchFailed,
    #[error("invalid SNP BSP state: {0}")]
    InvalidBspState(&'static str),
    #[error("SNP IGVM VP contexts do not match the configured virtual processors")]
    InvalidIgvmTopology,
    #[error("SNP IGVM VMSA import markers do not match the supplied VP contexts")]
    InvalidIgvmVmsaImports,
    #[error("KVM requires SNP IGVM VMSA directives after all measured page directives")]
    UnsupportedIgvmVmsaOrder,
    #[error("SNP IGVM VMSA GPA {0:#x} is not supported by KVM")]
    InvalidVmsaGpa(u64),
    #[error("invalid SNP IGVM VMSA: {0}")]
    InvalidIgvmVmsa(&'static str),
    #[error("KVM does not support SNP VMSA feature bits {0:#x}")]
    UnsupportedVmsaFeatures(u64),
    #[error("SNP IGVM requests unsupported highest VTL {0}")]
    UnsupportedVtl(u8),
    #[error("SNP IGVM requests unsupported shared GPA boundary {0:#x}")]
    UnsupportedSharedGpaBoundary(u64),
    #[error("KVM does not support SNP IGVM relocation")]
    IgvmRelocationUnsupported,
    #[error("KVM SNP operation failed")]
    Kvm(#[from] kvm::Error),
    #[error(transparent)]
    Memory(#[from] MemoryError),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Progress of the one-shot SNP launch sequence.
pub(crate) enum SnpLaunchState {
    /// No launch command has been issued.
    NotStarted,
    /// Launch is in progress.
    Started,
    /// Launch completed successfully.
    Finished,
    /// Launch failed and cannot be retried on this partition.
    Failed,
}

#[derive(Debug)]
pub(crate) struct KvmSnpVpConfig {
    pub(crate) context: Arc<virt::SnpVpContext>,
    pub(crate) vmsa: x86defs::snp::SevVmsa,
}

#[derive(Debug)]
pub(crate) struct KvmSnpConfig {
    pub(crate) generic: Arc<virt::SnpConfig>,
    pub(crate) vps: Vec<KvmSnpVpConfig>,
    pub(crate) vmsa_features: u64,
}

impl KvmSnpConfig {
    pub(crate) fn vp(&self, vp_index: virt::VpIndex) -> Option<&KvmSnpVpConfig> {
        self.vps
            .binary_search_by_key(&vp_index, |vp| vp.context.vp_index)
            .ok()
            .map(|index| &self.vps[index])
    }
}

fn parse_vmsa_page(context: Arc<virt::SnpVpContext>) -> Result<KvmSnpVpConfig, SnpError> {
    let (vmsa, _) = x86defs::snp::SevVmsa::read_from_prefix(context.page.as_ref())
        .map_err(|_| SnpError::InvalidIgvmVmsa("invalid VMSA page size"))?;
    Ok(KvmSnpVpConfig { context, vmsa })
}

pub(crate) fn prepare_snp_config(
    config: Arc<virt::SnpConfig>,
    supported_vmsa_features: u64,
) -> Result<Arc<KvmSnpConfig>, SnpError> {
    if config.highest_vtl != 0 {
        return Err(SnpError::UnsupportedVtl(config.highest_vtl));
    }
    if config.shared_gpa_boundary != 0 {
        return Err(SnpError::UnsupportedSharedGpaBoundary(
            config.shared_gpa_boundary,
        ));
    }
    if config.has_relocation {
        return Err(SnpError::IgvmRelocationUnsupported);
    }
    if config.vp_contexts.is_empty() {
        return Err(SnpError::InvalidIgvmTopology);
    }

    // KVM_SEV_INIT2 needs the VM-wide VMSA feature bits before any vCPUs
    // exist. KVM does not import these raw pages directly: before launch finish
    // we install each page's state into its vCPU, then KVM synthesizes and
    // measures its own VMSAs at the reserved initial-VMSA GPA.
    let mut vps = Vec::with_capacity(config.vp_contexts.len());
    let mut vmsa_features = None;
    for context in &config.vp_contexts {
        let vp = parse_vmsa_page(context.clone())?;
        if vp.vmsa.sev_features.vtom() || vp.vmsa.virtual_tom != 0 {
            return Err(SnpError::InvalidIgvmVmsa("vTOM is not supported"));
        }
        let features = u64::from(vp.vmsa.sev_features) & !1;
        match vmsa_features {
            Some(previous) if previous != features => {
                return Err(SnpError::InvalidIgvmVmsa(
                    "VP contexts have inconsistent VMSA features",
                ));
            }
            None => vmsa_features = Some(features),
            _ => {}
        }
        vps.push(vp);
    }
    vps.sort_by_key(|vp| vp.context.vp_index);
    let vmsa_features = vmsa_features.unwrap_or(0);
    let unsupported_features = vmsa_features & !supported_vmsa_features;
    if unsupported_features != 0 {
        return Err(SnpError::UnsupportedVmsaFeatures(unsupported_features));
    }

    Ok(Arc::new(KvmSnpConfig {
        generic: config,
        vps,
        vmsa_features,
    }))
}

impl virt::AcceptInitialPages for KvmPartition {
    type Error = KvmError;

    fn accept_initial_pages(&self, pages: &[virt::InitialPageImport]) -> Result<(), Self::Error> {
        self.inner.snp_launch_initial_pages(pages)?;
        Ok(())
    }
}

impl KvmPartitionInner {
    /// Runs the SNP launch sequence once and records its terminal state.
    fn snp_launch_initial_pages(&self, pages: &[virt::InitialPageImport]) -> Result<(), SnpError> {
        {
            let mut state = self.snp_launch_state.lock();
            match *state {
                SnpLaunchState::NotStarted => *state = SnpLaunchState::Started,
                SnpLaunchState::Started => return Err(SnpError::LaunchInProgress),
                SnpLaunchState::Finished => return Err(SnpError::LaunchAlreadyFinished),
                SnpLaunchState::Failed => return Err(SnpError::LaunchFailed),
            }
        }

        tracing::info!(page_ranges = pages.len(), "starting SNP launch");
        match self.snp_launch_initial_pages_inner(pages) {
            Ok(()) => {
                *self.snp_launch_state.lock() = SnpLaunchState::Finished;
                tracing::info!("finished SNP launch");
                Ok(())
            }
            Err(err) => {
                *self.snp_launch_state.lock() = SnpLaunchState::Failed;
                tracing::error!(error = &err as &dyn std::error::Error, "failed SNP launch");
                Err(err)
            }
        }
    }

    /// Adds every loader-provided range to the SNP launch context and finalizes it.
    fn snp_launch_initial_pages_inner(
        &self,
        pages: &[virt::InitialPageImport],
    ) -> Result<(), SnpError> {
        let sev = self.sev.as_ref().ok_or(SnpError::IsolationNotSupported)?;
        if let Some(config) = &self.snp_config {
            validate_snp_igvm_vmsa_imports(pages, &config.generic)?;
        } else {
            self.apply_snp_vmsa(pages)?;
        }
        self.kvm.check_sev_snp_launch_extensions()?;
        let mut launch_start = kvm::kvm_sev_snp_launch_start {
            policy: self
                .snp_config
                .as_ref()
                .map_or((1 << 19) | (1 << 17) | (1 << 16), |config| {
                    config.generic.policy
                }),
            ..Default::default()
        };
        tracing::debug!(policy = launch_start.policy, "KVM_SEV_SNP_LAUNCH_START");
        self.kvm
            .sev_snp_launch_start(sev.as_fd(), &mut launch_start)?;

        for page in pages {
            if page.import_type == InitialPageImportType::Shared {
                self.set_initial_shared_memory(page.range)?;
                continue;
            }
            if self.snp_config.is_some() && page.import_type == InitialPageImportType::VpContext {
                // KVM synthesizes and measures IGVM VMSAs from vCPU register
                // state during launch finish.
                continue;
            }

            let kvm_page_type = crate::arch::snp::snp_launch_page_type(page.import_type)?;

            let private_range = {
                let memory = self.memory.lock();
                private_memory_range_from_slots(page.range, &memory.ranges)
                    .map_err(map_snp_private_range_error)?
            };
            if page.import_type == InitialPageImportType::Cpuid {
                tracing::debug!(
                    gpa = page.range.start(),
                    len = page.range.len(),
                    cpuid_entries = self.bsp_cpuid.len(),
                    "writing SNP CPUID page"
                );
                let (xcr0, xss) = self
                    .snp_config
                    .as_ref()
                    .and_then(|config| config.vp(virt::VpIndex::BSP))
                    .map_or((1, 0), |vp| (vp.vmsa.xcr0, vp.vmsa.xss));
                write_snp_cpuid_page(
                    private_range.hva,
                    page.range.len(),
                    &self.bsp_cpuid,
                    xcr0,
                    xss,
                )?;
            }
            let gpa = page.range.start();
            tracing::trace!(
                gpa,
                len = page.range.len(),
                ?kvm_page_type,
                import_type = ?page.import_type,
                tag = page.tag,
                "KVM_SEV_SNP_LAUNCH_UPDATE"
            );
            self.kvm.sev_snp_launch_update(
                sev.as_fd(),
                gpa / hvdef::HV_PAGE_SIZE,
                private_range.hva as u64,
                page.range.len(),
                kvm_page_type,
            )?;
        }
        self.prepare_snp_vmsa_register_state()?;
        tracing::debug!("KVM_SEV_SNP_LAUNCH_FINISH");
        if let Some(identity) = self
            .snp_config
            .as_ref()
            .and_then(|config| config.generic.identity.as_ref())
        {
            let id_block = virt::x86::snp::snp_id_block(identity, launch_start.policy);
            let id_auth = virt::x86::snp::snp_id_auth(identity);
            let mut finish = kvm::kvm_sev_snp_launch_finish {
                id_block_uaddr: id_block.as_bytes().as_ptr() as u64,
                id_auth_uaddr: id_auth.as_ptr() as u64,
                id_block_en: 1,
                auth_key_en: (identity.author_key_enabled != 0).into(),
                vcek_disabled: 0,
                host_data: [0; 32],
                ..Default::default()
            };
            self.kvm.sev_snp_launch_finish(sev.as_fd(), &mut finish)?;
        } else {
            self.kvm
                .sev_snp_launch_finish(sev.as_fd(), &mut Default::default())?;
        }
        Ok(())
    }

    // TODO: Remove this register translation once KVM supports importing a
    // loader-provided VMSA directly.
    fn apply_snp_vmsa(&self, pages: &[virt::InitialPageImport]) -> Result<(), SnpError> {
        let mut vmsa_pages = pages
            .iter()
            .filter(|page| page.import_type == InitialPageImportType::VpContext);
        let page = vmsa_pages.next().ok_or(SnpError::MissingVmsa)?;
        if vmsa_pages.next().is_some() {
            return Err(SnpError::MultipleVmsa);
        }
        if page.range.len() != hvdef::HV_PAGE_SIZE {
            return Err(SnpError::InvalidLaunchRange);
        }

        let vmsa = self
            .gm
            .read_plain::<x86defs::snp::SevVmsa>(page.range.start())
            .map_err(SnpError::VmsaMemory)?;
        let state = virt::x86::snp::state_from_vmsa(&vmsa).map_err(SnpError::InvalidVmsa)?;
        let kvm_vp = self.vp_kvm(virt::VpIndex::BSP);
        let registers = state.registers;
        let regs = kvm::kvm_regs {
            rax: registers.rax,
            rbx: registers.rbx,
            rcx: registers.rcx,
            rdx: registers.rdx,
            rsi: registers.rsi,
            rdi: registers.rdi,
            rsp: registers.rsp,
            rbp: registers.rbp,
            r8: registers.r8,
            r9: registers.r9,
            r10: registers.r10,
            r11: registers.r11,
            r12: registers.r12,
            r13: registers.r13,
            r14: registers.r14,
            r15: registers.r15,
            rip: registers.rip,
            rflags: registers.rflags,
        };
        let old_sregs = kvm_vp.get_sregs()?;
        let sregs = kvm::kvm_sregs {
            cs: crate::arch::seg_reg(registers.cs),
            ds: crate::arch::seg_reg(registers.ds),
            es: crate::arch::seg_reg(registers.es),
            fs: crate::arch::seg_reg(registers.fs),
            gs: crate::arch::seg_reg(registers.gs),
            ss: crate::arch::seg_reg(registers.ss),
            tr: crate::arch::seg_reg(registers.tr),
            ldt: crate::arch::seg_reg(registers.ldtr),
            gdt: crate::arch::table_reg(registers.gdtr),
            idt: crate::arch::table_reg(registers.idtr),
            cr0: registers.cr0,
            cr2: registers.cr2,
            cr3: registers.cr3,
            cr4: registers.cr4,
            cr8: registers.cr8,
            efer: registers.efer,
            interrupt_bitmap: [0; 4],
            ..old_sregs
        };

        kvm_vp.set_regs(&regs)?;
        kvm_vp.set_sregs(&sregs)?;
        kvm_vp.set_msrs(&[(x86defs::X86X_MSR_CR_PAT, state.pat)])?;
        kvm_vp.set_xcr0(state.xcr0)?;
        Ok(())
    }

    /// Prepares the vCPU state that KVM will encode into each SNP VMSA.
    ///
    /// KVM owns the VMSA pages and does not expose them as launch imports.
    /// During `KVM_SEV_SNP_LAUNCH_FINISH`, KVM copies each vCPU's current
    /// register, VMCB, and FPU state into its VMSA before measuring and
    /// encrypting it. Normalize the required XCR0 state for every vCPU and
    /// validate the direct-boot BSP before that state becomes protected.
    ///
    /// AP register state is not validated here because SNP APs are started
    /// later through GHCB AP creation with guest-provided VMSAs.
    fn prepare_snp_vmsa_register_state(&self) -> Result<(), SnpError> {
        for vp in &self.vps {
            let vp_info = vp.vp_info();
            let kvm_vp = self.kvm.vp(vp_info.apic_id);
            if let Some(config) = &self.snp_config {
                let vp = config
                    .vp(vp_info.base.vp_index)
                    .ok_or(SnpError::InvalidIgvmTopology)?;
                set_snp_igvm_vmsa_state(&kvm_vp, &vp.vmsa)?;
            }
            let sregs = kvm_vp.get_sregs()?;

            let xcr0 = kvm_vp.get_xcr0()?;
            if xcr0 & x86defs::xsave::XFEATURE_X87 == 0 {
                kvm_vp.set_xcr0(xcr0 | x86defs::xsave::XFEATURE_X87)?;
            }

            if vp_info.base.vp_index.is_bsp() {
                validate_snp_bsp_register_state(&kvm_vp.get_regs()?, &sregs)?;
            }
        }

        Ok(())
    }
}

fn validate_snp_igvm_vmsa_imports(
    pages: &[virt::InitialPageImport],
    config: &virt::SnpConfig,
) -> Result<(), SnpError> {
    let mut imports = pages
        .iter()
        .filter(|page| page.import_type == InitialPageImportType::VpContext);
    for context in &config.vp_contexts {
        let Some(import) = imports.next() else {
            return Err(SnpError::InvalidIgvmVmsaImports);
        };
        if import.range.start() != context.gpa || import.range.len() != hvdef::HV_PAGE_SIZE {
            return Err(SnpError::InvalidIgvmVmsaImports);
        }
    }
    if imports.next().is_some() {
        return Err(SnpError::InvalidIgvmVmsaImports);
    }

    let contexts_are_ordered = config
        .vp_contexts
        .windows(2)
        .all(|contexts| contexts[0].vp_index < contexts[1].vp_index);
    let mut saw_vmsa = false;
    let vmsa_is_suffix = pages.iter().all(|page| match page.import_type {
        InitialPageImportType::VpContext => {
            saw_vmsa = true;
            true
        }
        InitialPageImportType::Shared => true,
        _ => !saw_vmsa,
    });
    if !contexts_are_ordered || !vmsa_is_suffix {
        return Err(SnpError::UnsupportedIgvmVmsaOrder);
    }

    Ok(())
}

fn segment_from_vmsa(segment: x86defs::snp::SevSelector) -> kvm::kvm_segment {
    kvm::kvm_segment {
        base: segment.base,
        limit: segment.limit,
        selector: segment.selector,
        type_: (segment.attrib & 0xf) as u8,
        present: ((segment.attrib >> 7) & 1) as u8,
        dpl: ((segment.attrib >> 5) & 3) as u8,
        db: ((segment.attrib >> 10) & 1) as u8,
        s: ((segment.attrib >> 4) & 1) as u8,
        l: ((segment.attrib >> 9) & 1) as u8,
        g: ((segment.attrib >> 11) & 1) as u8,
        avl: ((segment.attrib >> 8) & 1) as u8,
        unusable: 0,
        padding: 0,
    }
}

fn table_from_vmsa(table: x86defs::snp::SevSelector) -> kvm::kvm_dtable {
    kvm::kvm_dtable {
        base: table.base,
        limit: table.limit as u16,
        padding: [0; 3],
    }
}

fn set_snp_igvm_vmsa_state(
    kvm_vp: &kvm::Processor<'_>,
    vmsa: &x86defs::snp::SevVmsa,
) -> Result<(), SnpError> {
    let regs = kvm::kvm_regs {
        rax: vmsa.rax,
        rbx: vmsa.rbx,
        rcx: vmsa.rcx,
        rdx: vmsa.rdx,
        rsi: vmsa.rsi,
        rdi: vmsa.rdi,
        rsp: vmsa.rsp,
        rbp: vmsa.rbp,
        r8: vmsa.r8,
        r9: vmsa.r9,
        r10: vmsa.r10,
        r11: vmsa.r11,
        r12: vmsa.r12,
        r13: vmsa.r13,
        r14: vmsa.r14,
        r15: vmsa.r15,
        rip: vmsa.rip,
        rflags: vmsa.rflags,
    };
    let mut sregs = kvm_vp.get_sregs()?;
    sregs.cs = segment_from_vmsa(vmsa.cs);
    sregs.ds = segment_from_vmsa(vmsa.ds);
    sregs.es = segment_from_vmsa(vmsa.es);
    sregs.fs = segment_from_vmsa(vmsa.fs);
    sregs.gs = segment_from_vmsa(vmsa.gs);
    sregs.ss = segment_from_vmsa(vmsa.ss);
    sregs.tr = segment_from_vmsa(vmsa.tr);
    sregs.ldt = segment_from_vmsa(vmsa.ldtr);
    sregs.gdt = table_from_vmsa(vmsa.gdtr);
    sregs.idt = table_from_vmsa(vmsa.idtr);
    sregs.cr0 = vmsa.cr0;
    sregs.cr2 = vmsa.cr2;
    sregs.cr3 = vmsa.cr3;
    sregs.cr4 = vmsa.cr4;
    sregs.cr8 = 0;
    sregs.efer = vmsa.efer & !x86defs::X64_EFER_SVME;
    sregs.interrupt_bitmap = [0; 4];

    kvm_vp.set_regs(&regs)?;
    kvm_vp.set_sregs(&sregs)?;
    kvm_vp.set_debug_regs(&kvm::DebugRegisters {
        db: [vmsa.dr0, vmsa.dr1, vmsa.dr2, vmsa.dr3],
        dr6: vmsa.dr6,
        dr7: vmsa.dr7,
    })?;
    kvm_vp.set_xcr0(vmsa.xcr0)?;
    kvm_vp.set_msrs(&[
        (x86defs::X86X_MSR_CR_PAT, vmsa.pat),
        (x86defs::X86X_MSR_XSS, vmsa.xss),
    ])?;

    let mut xsave = [0; 4096];
    xsave[0..2].copy_from_slice(&vmsa.x87_fcw.to_le_bytes());
    xsave[2..4].copy_from_slice(&vmsa.x87_fsw.to_le_bytes());
    xsave[4] = vmsa.x87_ftw as u8;
    xsave[6..8].copy_from_slice(&vmsa.x87_op.to_le_bytes());
    xsave[8..16].copy_from_slice(&vmsa.x87_rip.to_le_bytes());
    xsave[16..24].copy_from_slice(&vmsa.x87dp.to_le_bytes());
    xsave[24..28].copy_from_slice(&vmsa.mxcsr.to_le_bytes());
    kvm_vp.set_xsave(&xsave)?;
    Ok(())
}

/// Validates the BSP state that KVM will seal into the initial VMSA.
///
/// This catches loader or register-plumbing errors before launch finish, where
/// they would otherwise surface as a firmware error or a guest that cannot
/// execute the direct Linux entry point.
fn validate_snp_bsp_register_state(
    regs: &kvm::kvm_regs,
    sregs: &kvm::kvm_sregs,
) -> Result<(), SnpError> {
    const REQUIRED_CR0: u64 = x86defs::X64_CR0_PE | x86defs::X64_CR0_PG;
    const REQUIRED_CR4: u64 = x86defs::X64_CR4_PAE;
    const REQUIRED_EFER: u64 =
        x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA | x86defs::X64_EFER_NXE;

    if sregs.cr0 & REQUIRED_CR0 != REQUIRED_CR0 {
        return Err(SnpError::InvalidBspState("CR0"));
    }
    if sregs.cr3 == 0 {
        return Err(SnpError::InvalidBspState("CR3"));
    }
    if sregs.cr4 & REQUIRED_CR4 != REQUIRED_CR4 {
        return Err(SnpError::InvalidBspState("CR4"));
    }
    if sregs.efer & REQUIRED_EFER != REQUIRED_EFER {
        return Err(SnpError::InvalidBspState("EFER"));
    }
    if sregs.cs.present == 0 || sregs.cs.l == 0 {
        return Err(SnpError::InvalidBspState("CS"));
    }
    if regs.rip == 0 {
        return Err(SnpError::InvalidBspState("RIP"));
    }

    tracing::debug!(
        rip = regs.rip,
        rsi = regs.rsi,
        cr0 = sregs.cr0,
        cr3 = sregs.cr3,
        cr4 = sregs.cr4,
        efer = sregs.efer,
        vmsa_efer = sregs.efer | x86defs::X64_EFER_SVME,
        cs_selector = sregs.cs.selector,
        cs_base = sregs.cs.base,
        cs_limit = sregs.cs.limit,
        cs_type = sregs.cs.type_,
        ds_selector = sregs.ds.selector,
        es_selector = sregs.es.selector,
        ss_selector = sregs.ss.selector,
        "validated SNP BSP register state"
    );

    Ok(())
}

const SNP_CPUID_COUNT_MAX: usize = 64;
const SNP_CPUID_TABLE_HEADER_SIZE: usize = 16;
const SNP_CPUID_FN_SIZE: usize = 48;

/// Serializes the effective BSP CPUID table in the SNP firmware page format.
///
/// Entries that become all-zero after firmware-required sanitization are
/// omitted so the fixed 64-entry firmware limit is applied to the serialized
/// table rather than the unsanitized KVM table.
fn write_snp_cpuid_page(
    page: *mut u8,
    page_len: u64,
    cpuid: &[kvm::kvm_cpuid_entry2],
    initial_xcr0: u64,
    initial_xss: u64,
) -> Result<(), SnpError> {
    if page_len < (SNP_CPUID_TABLE_HEADER_SIZE + SNP_CPUID_COUNT_MAX * SNP_CPUID_FN_SIZE) as u64 {
        return Err(SnpError::InvalidLaunchRange);
    }

    let cpuid = cpuid
        .iter()
        .copied()
        .filter_map(|mut entry| {
            sanitize_snp_cpuid_entry(&mut entry);
            (entry.eax != 0 || entry.ebx != 0 || entry.ecx != 0 || entry.edx != 0).then_some(entry)
        })
        .collect::<Vec<_>>();
    if cpuid.len() > SNP_CPUID_COUNT_MAX {
        return Err(SnpError::TooManyCpuidEntries(cpuid.len()));
    }

    let page = unsafe { std::slice::from_raw_parts_mut(page, page_len as usize) };
    page.fill(0);
    page[..4].copy_from_slice(&(cpuid.len() as u32).to_le_bytes());

    for (index, cpuid) in cpuid.iter().copied().enumerate() {
        let entry = &mut page[SNP_CPUID_TABLE_HEADER_SIZE + index * SNP_CPUID_FN_SIZE..]
            [..SNP_CPUID_FN_SIZE];
        entry[0..4].copy_from_slice(&cpuid.function.to_le_bytes());
        entry[4..8].copy_from_slice(&cpuid.index.to_le_bytes());
        let initial_xsave_leaf = cpuid.function
            == x86defs::cpuid::CpuidFunction::ExtendedStateEnumeration.0
            && (cpuid.index == 0 || cpuid.index == 1);
        let (xcr0, xss) = if initial_xsave_leaf {
            (initial_xcr0, initial_xss)
        } else {
            (0_u64, 0_u64)
        };
        entry[8..16].copy_from_slice(&xcr0.to_le_bytes());
        entry[16..24].copy_from_slice(&xss.to_le_bytes());
        entry[24..28].copy_from_slice(&cpuid.eax.to_le_bytes());
        let ebx = if initial_xsave_leaf { 0x240 } else { cpuid.ebx };
        entry[28..32].copy_from_slice(&ebx.to_le_bytes());
        entry[32..36].copy_from_slice(&cpuid.ecx.to_le_bytes());
        entry[36..40].copy_from_slice(&cpuid.edx.to_le_bytes());
    }

    Ok(())
}

/// Removes KVM-synthetic CPUID bits that SNP firmware validates against hardware.
fn sanitize_snp_cpuid_entry(entry: &mut kvm::kvm_cpuid_entry2) {
    match (entry.function, entry.index) {
        // SNP firmware validates the CPUID page against hardware-supported
        // CPUID values, not KVM's synthetic guest CPUID additions.
        (0x1, _) => entry.ecx &= !0x01000000,
        (0x7, 0) => {
            entry.ebx &= !0x2;
            entry.edx = 0;
        }
        (0x80000008, _) => entry.ebx &= !0x02000000,
        (0x80000021, _) => {
            entry.eax &= !0x200;
            entry.ecx = 0;
        }
        _ => {}
    }
}

/// Converts a generic private-slot lookup failure into the SNP launch error.
fn map_snp_private_range_error(err: MemoryError) -> SnpError {
    match err {
        MemoryError::InvalidPrivateMemoryRange | MemoryError::InvalidMapGpaRange => {
            SnpError::InvalidLaunchRange
        }
        err => SnpError::Memory(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;
    use zerocopy::FromZeros;

    fn valid_vmsa_page_at_rip(features: x86defs::snp::SevFeatures, rip: u64) -> Arc<[u8; 4096]> {
        let mut vmsa = x86defs::snp::SevVmsa::new_zeroed();
        vmsa.efer = x86defs::X64_EFER_SVME
            | x86defs::X64_EFER_LME
            | x86defs::X64_EFER_LMA
            | x86defs::X64_EFER_NXE;
        vmsa.cr4 = x86defs::X64_CR4_MCE | x86defs::X64_CR4_PAE;
        vmsa.cr3 = (1 << 51) | 0x1000;
        vmsa.cr0 = x86defs::X64_CR0_ET | x86defs::X64_CR0_PE | x86defs::X64_CR0_PG;
        vmsa.dr7 = 0x400;
        vmsa.dr6 = 0xffff_0ff0;
        vmsa.rflags = 2;
        vmsa.rip = rip;
        vmsa.sev_features = features;
        vmsa.xcr0 = 1;
        vmsa.x87_fcw = x86defs::xsave::INIT_FCW;
        vmsa.mxcsr = x86defs::xsave::DEFAULT_MXCSR;

        let mut page = [0; 4096];
        page[..size_of::<x86defs::snp::SevVmsa>()].copy_from_slice(vmsa.as_bytes());
        Arc::new(page)
    }

    fn valid_vmsa_page(features: x86defs::snp::SevFeatures) -> Arc<[u8; 4096]> {
        valid_vmsa_page_at_rip(features, 0x100000)
    }

    fn vp_context(vp_index: u32, page: Arc<[u8; 4096]>) -> Arc<virt::SnpVpContext> {
        Arc::new(virt::SnpVpContext {
            gpa: KVM_SNP_VMSA_GPA,
            vp_index: virt::VpIndex::new(vp_index),
            page,
        })
    }

    fn snp_config_with_contexts(vp_contexts: Vec<Arc<virt::SnpVpContext>>) -> Arc<virt::SnpConfig> {
        Arc::new(virt::SnpConfig {
            policy: 0x30000,
            highest_vtl: 0,
            shared_gpa_boundary: 0,
            has_relocation: false,
            vp_contexts,
            identity: None,
        })
    }

    fn snp_config(page: Arc<[u8; 4096]>) -> Arc<virt::SnpConfig> {
        snp_config_with_contexts(vec![vp_context(0, page)])
    }

    fn page_import(gpa: u64, import_type: InitialPageImportType) -> virt::InitialPageImport {
        virt::InitialPageImport {
            range: memory_range::MemoryRange::new(gpa..gpa + hvdef::HV_PAGE_SIZE),
            import_type,
            tag: "test",
        }
    }

    #[test]
    fn validates_kvm_igvm_vmsa_import_markers() {
        let features = x86defs::snp::SevFeatures::new().with_snp(true);
        let config = snp_config(valid_vmsa_page(features));
        let pages = [
            page_import(0x1000, InitialPageImportType::Normal),
            page_import(KVM_SNP_VMSA_GPA, InitialPageImportType::VpContext),
        ];

        validate_snp_igvm_vmsa_imports(&pages, &config).unwrap();

        let missing = [page_import(0x1000, InitialPageImportType::Normal)];
        assert!(matches!(
            validate_snp_igvm_vmsa_imports(&missing, &config),
            Err(SnpError::InvalidIgvmVmsaImports)
        ));
    }

    #[test]
    fn rejects_interleaved_vmsa_for_kvm_igvm() {
        let features = x86defs::snp::SevFeatures::new().with_snp(true);
        let config = snp_config(valid_vmsa_page(features));
        let pages = [
            page_import(KVM_SNP_VMSA_GPA, InitialPageImportType::VpContext),
            page_import(0x1000, InitialPageImportType::Normal),
        ];

        assert!(matches!(
            validate_snp_igvm_vmsa_imports(&pages, &config),
            Err(SnpError::UnsupportedIgvmVmsaOrder)
        ));
    }
    #[test]
    fn propagates_supported_nonzero_vmsa_features() {
        let features = x86defs::snp::SevFeatures::new()
            .with_snp(true)
            .with_restrict_injection(true);
        let supported = u64::from(features) & !1;
        let prepared =
            prepare_snp_config(snp_config(valid_vmsa_page(features)), supported).unwrap();
        assert_eq!(prepared.vmsa_features, supported);

        assert!(matches!(
            prepare_snp_config(
                snp_config(valid_vmsa_page(features)),
                0,
            ),
            Err(SnpError::UnsupportedVmsaFeatures(bits)) if bits == supported
        ));
    }

    #[test]
    fn maps_multiple_vp_contexts_by_vp_index() {
        let features = x86defs::snp::SevFeatures::new().with_snp(true);
        let prepared = prepare_snp_config(
            snp_config_with_contexts(vec![
                vp_context(1, valid_vmsa_page_at_rip(features, 0x200000)),
                vp_context(0, valid_vmsa_page_at_rip(features, 0x100000)),
            ]),
            u64::MAX,
        )
        .unwrap();

        assert_eq!(prepared.vps.len(), 2);
        assert_eq!(prepared.vp(virt::VpIndex::BSP).unwrap().vmsa.rip, 0x100000);
        assert_eq!(
            prepared.vp(virt::VpIndex::new(1)).unwrap().vmsa.rip,
            0x200000
        );
    }

    #[test]
    fn rejects_inconsistent_multi_vp_vmsa_features() {
        let bsp_features = x86defs::snp::SevFeatures::new().with_snp(true);
        let ap_features = bsp_features.with_restrict_injection(true);
        assert!(matches!(
            prepare_snp_config(
                snp_config_with_contexts(vec![
                    vp_context(0, valid_vmsa_page(bsp_features)),
                    vp_context(1, valid_vmsa_page(ap_features)),
                ]),
                u64::MAX,
            ),
            Err(SnpError::InvalidIgvmVmsa(
                "VP contexts have inconsistent VMSA features"
            ))
        ));
    }

    #[test]
    fn write_snp_cpuid_page_writes_linux_table_and_xsave_inputs() {
        let mut page = vec![0xff; hvdef::HV_PAGE_SIZE as usize];
        let cpuid = [
            kvm::kvm_cpuid_entry2 {
                function: 1,
                index: 0,
                eax: 0x11,
                ebx: 0x12,
                ecx: 0x13,
                edx: 0x14,
                ..Default::default()
            },
            kvm::kvm_cpuid_entry2 {
                function: x86defs::cpuid::CpuidFunction::ExtendedStateEnumeration.0,
                index: 0,
                eax: 0x21,
                ebx: 0x22,
                ecx: 0x23,
                edx: 0x24,
                ..Default::default()
            },
        ];

        write_snp_cpuid_page(page.as_mut_ptr(), page.len() as u64, &cpuid, 1, 0).unwrap();

        assert_eq!(u32::from_le_bytes(page[0..4].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(page[16..20].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(page[40..44].try_into().unwrap()), 0x11);
        assert_eq!(u32::from_le_bytes(page[44..48].try_into().unwrap()), 0x12);
        let xsave = 16 + 48;
        assert_eq!(
            u32::from_le_bytes(page[xsave..xsave + 4].try_into().unwrap()),
            x86defs::cpuid::CpuidFunction::ExtendedStateEnumeration.0
        );
        assert_eq!(
            u64::from_le_bytes(page[xsave + 8..xsave + 16].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(page[xsave + 28..xsave + 32].try_into().unwrap()),
            0x240
        );
    }

    #[test]
    fn write_snp_cpuid_page_sparsifies_after_sanitizing() {
        let mut page = vec![0xff; hvdef::HV_PAGE_SIZE as usize];
        let cpuid = [
            kvm::kvm_cpuid_entry2 {
                function: 1,
                ecx: 0x0100_0000,
                ..Default::default()
            },
            kvm::kvm_cpuid_entry2 {
                function: 2,
                ..Default::default()
            },
            kvm::kvm_cpuid_entry2 {
                function: 0x4000_0000,
                eax: 0x4000_0001,
                ..Default::default()
            },
        ];

        write_snp_cpuid_page(page.as_mut_ptr(), page.len() as u64, &cpuid, 1, 0).unwrap();

        assert_eq!(u32::from_le_bytes(page[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(page[16..20].try_into().unwrap()),
            0x4000_0000
        );
    }

    #[test]
    fn write_snp_cpuid_page_enforces_limit_after_sparsifying() {
        let mut page = vec![0xff; hvdef::HV_PAGE_SIZE as usize];
        let mut cpuid = (0..SNP_CPUID_COUNT_MAX as u32)
            .map(|function| kvm::kvm_cpuid_entry2 {
                function,
                eax: 1,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        cpuid.push(kvm::kvm_cpuid_entry2 {
            function: 0xffff,
            ..Default::default()
        });

        write_snp_cpuid_page(page.as_mut_ptr(), page.len() as u64, &cpuid, 1, 0).unwrap();
        assert_eq!(
            u32::from_le_bytes(page[0..4].try_into().unwrap()),
            SNP_CPUID_COUNT_MAX as u32
        );

        cpuid.last_mut().unwrap().eax = 1;
        assert!(matches!(
            write_snp_cpuid_page(page.as_mut_ptr(), page.len() as u64, &cpuid, 1, 0),
            Err(SnpError::TooManyCpuidEntries(count)) if count == SNP_CPUID_COUNT_MAX + 1
        ));
    }
}
