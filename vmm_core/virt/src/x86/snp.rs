// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SEV-SNP launch helpers.
//!
//! [`vmsa_from_initial_regs`] is used by the shared direct-boot loader for SNP
//! backends, including KVM and MSHV. [`state_from_vmsa`] is currently used by
//! KVM to apply the loader-built VMSA through KVM's register-based launch path;
//! MSHV imports the VMSA page directly.

use super::SegmentRegister;
use super::TableRegister;
use super::X86InitialRegs;
use super::vp;
use thiserror::Error;
use x86defs::SegmentAttributes;
use x86defs::snp::SevSelector;
use x86defs::snp::SevVmsa;
use zerocopy::FromZeros;

const _: () = assert!(size_of::<SevVmsa>() <= hvdef::HV_PAGE_SIZE as usize);

/// The subset of initial VP state represented by a direct-boot SNP VMSA.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SnpVmsaState {
    /// Architectural register state.
    pub registers: vp::Registers,
    /// Page attribute table state.
    pub pat: u64,
    /// Extended control register 0.
    pub xcr0: u64,
    /// Whether restricted interrupt injection is enabled.
    pub restricted_injection: bool,
}

/// An error parsing a direct-boot SNP VMSA.
#[derive(Debug, Error)]
pub enum SnpVmsaError {
    /// The VMSA contains state outside the supported direct-boot contract.
    #[error("unsupported SNP VMSA state")]
    UnsupportedState,
}

/// Configuration for a direct-boot SNP VMSA.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct SnpVmsaConfig {
    /// Enables restricted interrupt injection.
    pub restricted_injection: bool,
}

/// Builds the PSP ID block for `id_block` and the launch `policy`.
pub fn snp_id_block(id_block: &crate::SnpIdBlock, policy: u64) -> x86defs::snp::SnpPspIdBlock {
    x86defs::snp::SnpPspIdBlock {
        ld: id_block.launch_digest,
        family_id: id_block.family_id,
        image_id: id_block.image_id,
        version: id_block.version,
        guest_svn: id_block.guest_svn,
        policy,
    }
}

/// Serializes the PSP ID authentication data for `id_block`.
pub fn snp_id_auth(id_block: &crate::SnpIdBlock) -> Box<[u8; 4096]> {
    const ID_BLOCK_SIGNATURE: usize = 64;
    const ID_KEY: usize = 576;
    const AUTHOR_KEY_SIGNATURE: usize = 1664;
    const AUTHOR_KEY: usize = 2176;

    fn write_signature(
        page: &mut [u8],
        offset: usize,
        signature: &x86defs::snp::SnpIdBlockSignature,
    ) {
        page[offset..offset + 72].copy_from_slice(&signature.r);
        page[offset + 72..offset + 144].copy_from_slice(&signature.s);
    }

    fn write_public_key(page: &mut [u8], offset: usize, key: &x86defs::snp::SnpIdBlockPublicKey) {
        page[offset..offset + 4].copy_from_slice(&key.curve.to_le_bytes());
        page[offset + 4..offset + 76].copy_from_slice(&key.qx);
        page[offset + 76..offset + 148].copy_from_slice(&key.qy);
    }

    let mut page = Box::new([0; 4096]);
    page[0..4].copy_from_slice(&id_block.id_key_algorithm.to_le_bytes());
    page[4..8].copy_from_slice(&id_block.author_key_algorithm.to_le_bytes());
    write_signature(&mut *page, ID_BLOCK_SIGNATURE, &id_block.id_key_signature);
    write_public_key(&mut *page, ID_KEY, &id_block.id_public_key);
    write_signature(
        &mut *page,
        AUTHOR_KEY_SIGNATURE,
        &id_block.author_key_signature,
    );
    write_public_key(&mut *page, AUTHOR_KEY, &id_block.author_public_key);
    page
}

/// Builds the direct-boot SNP VMSA corresponding to `initial`.
pub fn vmsa_from_initial_regs(initial: &X86InitialRegs, config: SnpVmsaConfig) -> SevVmsa {
    vmsa_from_state(&SnpVmsaState {
        registers: initial.registers,
        pat: initial.pat.value,
        xcr0: x86defs::xsave::XFEATURE_X87,
        restricted_injection: config.restricted_injection,
    })
}

/// Parses and validates a direct-boot SNP VMSA.
pub fn state_from_vmsa(vmsa: &SevVmsa) -> Result<SnpVmsaState, SnpVmsaError> {
    let state = SnpVmsaState {
        registers: vp::Registers {
            rax: vmsa.rax,
            rcx: vmsa.rcx,
            rdx: vmsa.rdx,
            rbx: vmsa.rbx,
            rbp: vmsa.rbp,
            rsp: vmsa.rsp,
            rsi: vmsa.rsi,
            rdi: vmsa.rdi,
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
            cs: segment_from_vmsa(vmsa.cs),
            ds: segment_from_vmsa(vmsa.ds),
            es: segment_from_vmsa(vmsa.es),
            fs: segment_from_vmsa(vmsa.fs),
            gs: segment_from_vmsa(vmsa.gs),
            ss: segment_from_vmsa(vmsa.ss),
            tr: segment_from_vmsa(vmsa.tr),
            ldtr: segment_from_vmsa(vmsa.ldtr),
            gdtr: table_from_vmsa(vmsa.gdtr),
            idtr: table_from_vmsa(vmsa.idtr),
            cr0: vmsa.cr0,
            cr2: vmsa.cr2,
            cr3: vmsa.cr3,
            cr4: vmsa.cr4,
            cr8: 0,
            efer: vmsa.efer & !x86defs::X64_EFER_SVME,
        },
        pat: vmsa.pat,
        xcr0: vmsa.xcr0,
        restricted_injection: vmsa.sev_features.restrict_injection(),
    };

    if &vmsa_from_state(&state) != vmsa {
        return Err(SnpVmsaError::UnsupportedState);
    }

    Ok(state)
}

fn vmsa_from_state(state: &SnpVmsaState) -> SevVmsa {
    let registers = &state.registers;
    let mut vmsa = SevVmsa::new_zeroed();

    vmsa.es = segment_to_vmsa(registers.es);
    vmsa.cs = segment_to_vmsa(registers.cs);
    vmsa.ss = segment_to_vmsa(registers.ss);
    vmsa.ds = segment_to_vmsa(registers.ds);
    vmsa.fs = segment_to_vmsa(registers.fs);
    vmsa.gs = segment_to_vmsa(registers.gs);
    vmsa.gdtr = table_to_vmsa(registers.gdtr);
    vmsa.ldtr = segment_to_vmsa(registers.ldtr);
    vmsa.idtr = table_to_vmsa(registers.idtr);
    vmsa.tr = segment_to_vmsa(registers.tr);
    vmsa.cpl = SegmentAttributes::from(registers.cs.attributes).descriptor_privilege_level();
    vmsa.efer = registers.efer | x86defs::X64_EFER_SVME;
    vmsa.cr4 = registers.cr4;
    vmsa.cr3 = registers.cr3;
    vmsa.cr0 = registers.cr0;
    vmsa.rflags = registers.rflags;
    vmsa.rip = registers.rip;
    vmsa.rsp = registers.rsp;
    vmsa.rax = registers.rax;
    vmsa.cr2 = registers.cr2;
    vmsa.pat = state.pat;
    vmsa.rcx = registers.rcx;
    vmsa.rdx = registers.rdx;
    vmsa.rbx = registers.rbx;
    vmsa.rbp = registers.rbp;
    vmsa.rsi = registers.rsi;
    vmsa.rdi = registers.rdi;
    vmsa.r8 = registers.r8;
    vmsa.r9 = registers.r9;
    vmsa.r10 = registers.r10;
    vmsa.r11 = registers.r11;
    vmsa.r12 = registers.r12;
    vmsa.r13 = registers.r13;
    vmsa.r14 = registers.r14;
    vmsa.r15 = registers.r15;
    vmsa.sev_features.set_snp(true);
    vmsa.sev_features
        .set_restrict_injection(state.restricted_injection);
    vmsa.xcr0 = state.xcr0;

    vmsa
}

fn segment_to_vmsa(register: SegmentRegister) -> SevSelector {
    SevSelector {
        selector: register.selector,
        attrib: (register.attributes & 0xff) | ((register.attributes >> 4) & 0xf00),
        limit: register.limit,
        base: register.base,
    }
}

fn segment_from_vmsa(selector: SevSelector) -> SegmentRegister {
    SegmentRegister {
        selector: selector.selector,
        attributes: (selector.attrib & 0xff) | ((selector.attrib & 0xf00) << 4),
        limit: selector.limit,
        base: selector.base,
    }
}

fn table_to_vmsa(register: TableRegister) -> SevSelector {
    SevSelector {
        selector: 0,
        attrib: 0,
        limit: register.limit as u32,
        base: register.base,
    }
}

fn table_from_vmsa(selector: SevSelector) -> TableRegister {
    TableRegister {
        limit: selector.limit as u16,
        base: selector.base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id_block() -> crate::SnpIdBlock {
        crate::SnpIdBlock {
            author_key_enabled: 1,
            launch_digest: [0x11; 48],
            family_id: [0x22; 16],
            image_id: [0x33; 16],
            version: 1,
            guest_svn: 7,
            id_key_algorithm: 0x01020304,
            author_key_algorithm: 0x05060708,
            id_key_signature: x86defs::snp::SnpIdBlockSignature {
                r: [0x44; 72],
                s: [0x55; 72],
            },
            id_public_key: x86defs::snp::SnpIdBlockPublicKey {
                curve: 2,
                qx: [0x66; 72],
                qy: [0x77; 72],
            },
            author_key_signature: x86defs::snp::SnpIdBlockSignature {
                r: [0x88; 72],
                s: [0x99; 72],
            },
            author_public_key: x86defs::snp::SnpIdBlockPublicKey {
                curve: 3,
                qx: [0xaa; 72],
                qy: [0xbb; 72],
            },
        }
    }

    #[test]
    fn snp_id_block_preserves_fields_and_policy() {
        let source = test_id_block();
        let id_block = snp_id_block(&source, 0x1234);

        assert_eq!(id_block.ld, source.launch_digest);
        assert_eq!(id_block.family_id, source.family_id);
        assert_eq!(id_block.image_id, source.image_id);
        assert_eq!(id_block.version, source.version);
        assert_eq!(id_block.guest_svn, source.guest_svn);
        assert_eq!(id_block.policy, 0x1234);
    }

    #[test]
    fn snp_id_auth_serializes_algorithms() {
        let id_block = test_id_block();
        let id_auth = snp_id_auth(&id_block);

        assert_eq!(&id_auth[0..4], &id_block.id_key_algorithm.to_le_bytes());
        assert_eq!(&id_auth[4..8], &id_block.author_key_algorithm.to_le_bytes());
    }

    #[test]
    fn snp_id_auth_serializes_signatures_and_keys_at_psp_offsets() {
        let id_block = test_id_block();
        let id_auth = snp_id_auth(&id_block);

        assert_eq!(&id_auth[64..136], &id_block.id_key_signature.r);
        assert_eq!(&id_auth[136..208], &id_block.id_key_signature.s);
        assert_eq!(
            &id_auth[576..580],
            &id_block.id_public_key.curve.to_le_bytes()
        );
        assert_eq!(&id_auth[580..652], &id_block.id_public_key.qx);
        assert_eq!(&id_auth[652..724], &id_block.id_public_key.qy);
        assert_eq!(&id_auth[1664..1736], &id_block.author_key_signature.r);
        assert_eq!(&id_auth[1736..1808], &id_block.author_key_signature.s);
        assert_eq!(
            &id_auth[2176..2180],
            &id_block.author_public_key.curve.to_le_bytes()
        );
        assert_eq!(&id_auth[2180..2252], &id_block.author_public_key.qx);
        assert_eq!(&id_auth[2252..2324], &id_block.author_public_key.qy);
    }

    #[test]
    fn snp_id_auth_zero_pads_reserved_bytes() {
        let id_auth = snp_id_auth(&test_id_block());

        for reserved in [8..64, 208..576, 724..1664, 1808..2176, 2324..4096] {
            assert!(id_auth[reserved].iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn direct_boot_vmsa_round_trips() {
        let initial = X86InitialRegs {
            registers: vp::Registers {
                rax: 1,
                rdx: 2,
                rip: 0x100000,
                rflags: 2,
                cs: SegmentRegister {
                    selector: 0x10,
                    attributes: 0xa09b,
                    limit: u32::MAX,
                    base: 0,
                },
                efer: x86defs::X64_EFER_LME | x86defs::X64_EFER_LMA,
                ..Default::default()
            },
            mtrrs: Default::default(),
            pat: vp::Pat {
                value: 0x7040600070406,
            },
        };

        let vmsa = vmsa_from_initial_regs(&initial, SnpVmsaConfig::default());
        let state = state_from_vmsa(&vmsa).unwrap();

        assert_eq!(state.registers, initial.registers);
        assert_eq!(state.pat, initial.pat.value);
        assert_eq!(state.xcr0, x86defs::xsave::XFEATURE_X87);
        assert!(vmsa.sev_features.snp());
        assert_ne!(vmsa.efer & x86defs::X64_EFER_SVME, 0);
    }

    #[test]
    fn rejects_unsupported_state() {
        let initial = X86InitialRegs {
            registers: Default::default(),
            mtrrs: Default::default(),
            pat: Default::default(),
        };
        let mut vmsa = vmsa_from_initial_regs(&initial, SnpVmsaConfig::default());
        vmsa.virtual_tom = 0x1000;

        assert!(matches!(
            state_from_vmsa(&vmsa),
            Err(SnpVmsaError::UnsupportedState)
        ));
    }

    #[test]
    fn enables_restricted_injection() {
        let initial = X86InitialRegs {
            registers: Default::default(),
            mtrrs: Default::default(),
            pat: Default::default(),
        };

        let vmsa = vmsa_from_initial_regs(
            &initial,
            SnpVmsaConfig {
                restricted_injection: true,
            },
        );

        assert!(vmsa.sev_features.restrict_injection());
        assert!(state_from_vmsa(&vmsa).unwrap().restricted_injection);
    }
}
