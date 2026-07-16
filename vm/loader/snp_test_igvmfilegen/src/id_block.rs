// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::Context;
use anyhow::ensure;
use crypto::ecdsa::EcdsaCurve;
use crypto::ecdsa::EcdsaKeyPair;
use igvm::IgvmDirectiveHeader;
use igvm_defs::IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY;
use igvm_defs::IGVM_VHS_SNP_ID_BLOCK_SIGNATURE;
use x86defs::snp::SnpPspIdBlock;
use zerocopy::IntoBytes;

const COMPATIBILITY_MASK: u32 = 1;
const SNP_ID_KEY_ALGORITHM_ECDSA_P384_SHA384: u32 = 1;
const SNP_ECDSA_CURVE_P384: u32 = 2;
const SNP_ECC_KEY_SIZE_BYTES: usize = 48;
const SNP_ECC_COMPONENT_SIZE_BYTES: usize = 72;
const FAMILY_ID: [u8; 16] = *b"OpenVMM SNP test";
const IMAGE_ID: [u8; 16] = *b"linux-direct\0\0\0\0";

pub fn signed_id_block(
    launch_digest: [u8; 48],
    guest_svn: u32,
    policy: u64,
) -> anyhow::Result<IgvmDirectiveHeader> {
    let id_block = SnpPspIdBlock {
        ld: launch_digest,
        version: 1,
        guest_svn,
        policy,
        family_id: FAMILY_ID,
        image_id: IMAGE_ID,
    };
    let (id_key_signature, id_public_key) = sign_id_block(&id_block)?;
    Ok(IgvmDirectiveHeader::SnpIdBlock {
        compatibility_mask: COMPATIBILITY_MASK,
        author_key_enabled: 0,
        reserved: [0; 3],
        ld: id_block.ld,
        family_id: id_block.family_id,
        image_id: id_block.image_id,
        version: id_block.version,
        guest_svn: id_block.guest_svn,
        id_key_algorithm: SNP_ID_KEY_ALGORITHM_ECDSA_P384_SHA384,
        author_key_algorithm: 0,
        id_key_signature: Box::new(id_key_signature),
        id_public_key: Box::new(id_public_key),
        author_key_signature: Box::new(IGVM_VHS_SNP_ID_BLOCK_SIGNATURE {
            r_comp: [0; SNP_ECC_COMPONENT_SIZE_BYTES],
            s_comp: [0; SNP_ECC_COMPONENT_SIZE_BYTES],
        }),
        author_public_key: Box::new(IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY {
            curve: 0,
            reserved: 0,
            qx: [0; SNP_ECC_COMPONENT_SIZE_BYTES],
            qy: [0; SNP_ECC_COMPONENT_SIZE_BYTES],
        }),
    })
}

fn sign_id_block(
    id_block: &SnpPspIdBlock,
) -> anyhow::Result<(
    IGVM_VHS_SNP_ID_BLOCK_SIGNATURE,
    IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
)> {
    let key = EcdsaKeyPair::generate(EcdsaCurve::P384)
        .context("generating temporary P-384 SNP ID key")?;
    let signature = key
        .sign(crypto::HashAlgorithm::Sha384, id_block.as_bytes())
        .context("signing SNP ID block")?;
    ensure!(
        signature.len() == SNP_ECC_KEY_SIZE_BYTES * 2,
        "unexpected P-384 signature size {}",
        signature.len()
    );
    let (sig_r, sig_s) = signature.split_at(SNP_ECC_KEY_SIZE_BYTES);

    let public_key = key
        .public_key_bytes()
        .context("exporting temporary SNP ID public key")?;
    ensure!(
        public_key.len() == SNP_ECC_KEY_SIZE_BYTES * 2,
        "unexpected P-384 public key size {}",
        public_key.len()
    );
    let (qx, qy) = public_key.split_at(SNP_ECC_KEY_SIZE_BYTES);

    Ok((
        IGVM_VHS_SNP_ID_BLOCK_SIGNATURE {
            r_comp: padded_le_component(sig_r),
            s_comp: padded_le_component(sig_s),
        },
        IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY {
            curve: SNP_ECDSA_CURVE_P384,
            reserved: 0,
            qx: padded_le_component(qx),
            qy: padded_le_component(qy),
        },
    ))
}

fn padded_le_component(input_be: &[u8]) -> [u8; SNP_ECC_COMPONENT_SIZE_BYTES] {
    let mut output = [0; SNP_ECC_COMPONENT_SIZE_BYTES];
    for (destination, source) in output.iter_mut().zip(input_be.iter().rev()) {
        *destination = *source;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn component_is_reversed_and_zero_padded() {
        let output = padded_le_component(&[1, 2, 3]);
        assert_eq!(&output[..3], &[3, 2, 1]);
        assert!(output[3..].iter().all(|byte| *byte == 0));
    }
}
