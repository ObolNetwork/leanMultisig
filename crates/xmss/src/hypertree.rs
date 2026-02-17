use utils::poseidon16_compress_pair;

use crate::*;

pub const MAX_HYPERTREE_DEPTH: usize = 3;
pub const MAX_HYPERTREE_LEAVES: usize = 1 << MAX_HYPERTREE_DEPTH; // 8

#[derive(Debug, Clone)]
pub struct ThresholdGroup {
    pub k: usize,
    pub n: usize,
    pub depth: usize,
    /// Level 0 = padded leaves, ..., level `depth` = [root].
    pub hypertree: Vec<Vec<Digest>>,
}

#[derive(Debug, Clone)]
pub struct ThresholdSignature {
    pub signer_indices: Vec<usize>,
    pub xmss_signatures: Vec<XmssSignature>,
}

fn next_power_of_two_exp(n: usize) -> usize {
    assert!(n >= 1);
    if n == 1 {
        return 0;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

impl ThresholdGroup {
    /// Build a threshold group from `k` (minimum signers) and the XMSS Merkle roots
    /// of `n` members. Pads to `2^depth` leaves with zero digests.
    pub fn new(k: usize, member_roots: &[Digest]) -> Self {
        let n = member_roots.len();
        assert!(k >= 1, "threshold must be at least 1");
        assert!(k <= n, "threshold k={k} exceeds group size n={n}");
        assert!(n <= MAX_HYPERTREE_LEAVES, "group size n={n} exceeds max {MAX_HYPERTREE_LEAVES}");

        let depth = if n <= 1 { 1 } else { next_power_of_two_exp(n) };
        assert!(depth <= MAX_HYPERTREE_DEPTH);

        let n_leaves = 1 << depth;
        let mut leaves = vec![[F::default(); DIGEST_SIZE]; n_leaves];
        leaves[..n].copy_from_slice(member_roots);

        let mut hypertree = vec![leaves];
        for level in 1..=depth {
            let prev = &hypertree[level - 1];
            let nodes: Vec<Digest> = prev
                .chunks_exact(2)
                .map(|pair| poseidon16_compress_pair(pair[0], pair[1]))
                .collect();
            hypertree.push(nodes);
        }

        Self { k, n, depth, hypertree }
    }

    pub fn root(&self) -> Digest {
        self.hypertree[self.depth][0]
    }

    pub fn leaves(&self) -> &[Digest] {
        &self.hypertree[0]
    }

    /// Extract `depth` sibling digests along the path from `leaf_index` to the root.
    pub fn merkle_proof(&self, leaf_index: usize) -> Vec<Digest> {
        assert!(leaf_index < (1 << self.depth));
        let mut proof = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;
        for level in 0..self.depth {
            let sibling = idx ^ 1;
            proof.push(self.hypertree[level][sibling]);
            idx >>= 1;
        }
        proof
    }

    /// Verify a Merkle proof for a single leaf.
    pub fn verify_merkle_proof(&self, leaf_index: usize, leaf: &Digest, proof: &[Digest]) -> bool {
        assert_eq!(proof.len(), self.depth);
        let mut current = *leaf;
        let mut idx = leaf_index;
        for (level, sibling) in proof.iter().enumerate().take(self.depth) {
            let is_left = (idx & 1) == 0;
            current = if is_left {
                poseidon16_compress_pair(current, *sibling)
            } else {
                poseidon16_compress_pair(*sibling, current)
            };
            idx >>= 1;
            let _ = level;
        }
        current == self.root()
    }
}

/// Verify a threshold signature natively (for testing).
/// Checks that `k` signers each signed the message and that their XMSS Merkle roots
/// are valid leaves of the hypertree.
pub fn threshold_verify(
    group: &ThresholdGroup,
    tsig: &ThresholdSignature,
    message: &[F; MESSAGE_LEN_FE],
) -> Result<(), ThresholdVerifyError> {
    if tsig.signer_indices.len() != tsig.xmss_signatures.len() {
        return Err(ThresholdVerifyError::SignatureCountMismatch);
    }
    let k = tsig.signer_indices.len();
    if k < group.k {
        return Err(ThresholdVerifyError::BelowThreshold);
    }

    // Check distinct indices
    let mut seen = std::collections::HashSet::new();
    for &idx in &tsig.signer_indices {
        if idx >= group.n {
            return Err(ThresholdVerifyError::InvalidSignerIndex);
        }
        if !seen.insert(idx) {
            return Err(ThresholdVerifyError::DuplicateSignerIndex);
        }
    }

    // Verify each signer
    for (i, &leaf_idx) in tsig.signer_indices.iter().enumerate() {
        let signer_root = group.leaves()[leaf_idx];
        let pub_key = XmssPublicKey { merkle_root: signer_root };

        // Verify XMSS signature
        xmss_verify(&pub_key, message, &tsig.xmss_signatures[i])
            .map_err(|_| ThresholdVerifyError::InvalidXmssSignature)?;

        // Verify hypertree Merkle proof
        let proof = group.merkle_proof(leaf_idx);
        if !group.verify_merkle_proof(leaf_idx, &signer_root, &proof) {
            return Err(ThresholdVerifyError::InvalidHypertreeProof);
        }
    }

    Ok(())
}

/// Verify a threshold signature and collect Poseidon traces (for proving).
pub fn threshold_verify_with_poseidon_trace(
    group: &ThresholdGroup,
    tsig: &ThresholdSignature,
    message: &[F; MESSAGE_LEN_FE],
) -> Result<Poseidon16History, ThresholdVerifyError> {
    let mut poseidon_trace = Vec::new();

    for (i, &leaf_idx) in tsig.signer_indices.iter().enumerate() {
        let signer_root = group.leaves()[leaf_idx];
        let pub_key = XmssPublicKey { merkle_root: signer_root };

        // Verify XMSS signature and collect traces
        let trace = xmss_verify_with_poseidon_trace(&pub_key, message, &tsig.xmss_signatures[i])
            .map_err(|_| ThresholdVerifyError::InvalidXmssSignature)?;
        poseidon_trace.extend(trace);

        // Trace hypertree Merkle path
        let proof = group.merkle_proof(leaf_idx);
        let mut current = signer_root;
        let mut idx = leaf_idx;
        for sibling in &proof {
            let is_left = (idx & 1) == 0;
            current = if is_left {
                poseidon16_compress_with_trace(&current, sibling, &mut poseidon_trace)
            } else {
                poseidon16_compress_with_trace(sibling, &current, &mut poseidon_trace)
            };
            idx >>= 1;
        }
        assert_eq!(current, group.root());
    }

    Ok(poseidon_trace)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdVerifyError {
    SignatureCountMismatch,
    BelowThreshold,
    InvalidSignerIndex,
    DuplicateSignerIndex,
    InvalidXmssSignature,
    InvalidHypertreeProof,
}

#[cfg(test)]
mod tests {
    use multilinear_toolkit::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    fn make_test_group(n: usize, k: usize) -> (ThresholdGroup, Vec<XmssSecretKey>, Vec<XmssPublicKey>) {
        let mut rng = StdRng::seed_from_u64(42);
        let mut secret_keys = Vec::new();
        let mut pub_keys = Vec::new();
        let mut roots = Vec::new();

        for _ in 0..n {
            let seed: [u8; 32] = rand::Rng::random(&mut rng);
            let (sk, pk) = xmss_key_gen(seed, 1000, 1200).unwrap();
            roots.push(pk.merkle_root);
            secret_keys.push(sk);
            pub_keys.push(pk);
        }

        let group = ThresholdGroup::new(k, &roots);
        (group, secret_keys, pub_keys)
    }

    #[test]
    fn test_hypertree_n4_depth2() {
        let (group, _, _) = make_test_group(4, 3);
        assert_eq!(group.depth, 2);
        assert_eq!(group.hypertree[0].len(), 4);
        assert_eq!(group.hypertree[1].len(), 2);
        assert_eq!(group.hypertree[2].len(), 1);

        // Verify Merkle proofs for all leaves
        for i in 0..4 {
            let proof = group.merkle_proof(i);
            assert_eq!(proof.len(), 2);
            assert!(group.verify_merkle_proof(i, &group.leaves()[i], &proof));
        }
    }

    #[test]
    fn test_hypertree_n7_depth3_padded() {
        let (group, _, _) = make_test_group(7, 5);
        assert_eq!(group.depth, 3);
        assert_eq!(group.hypertree[0].len(), 8); // padded to 8

        // Last leaf should be zero
        assert_eq!(group.leaves()[7], [F::default(); DIGEST_SIZE]);

        // Verify proofs for all original leaves
        for i in 0..7 {
            let proof = group.merkle_proof(i);
            assert_eq!(proof.len(), 3);
            assert!(group.verify_merkle_proof(i, &group.leaves()[i], &proof));
        }
    }

    #[test]
    fn test_hypertree_n2_depth1() {
        let (group, _, _) = make_test_group(2, 1);
        assert_eq!(group.depth, 1);
        assert_eq!(group.hypertree[0].len(), 2);
        assert_eq!(group.hypertree[1].len(), 1);

        for i in 0..2 {
            let proof = group.merkle_proof(i);
            assert_eq!(proof.len(), 1);
            assert!(group.verify_merkle_proof(i, &group.leaves()[i], &proof));
        }
    }

    #[test]
    fn test_invalid_merkle_proof() {
        let (group, _, _) = make_test_group(4, 2);
        let proof = group.merkle_proof(0);
        // Use wrong leaf
        let wrong_leaf = [F::from_usize(999); DIGEST_SIZE];
        assert!(!group.verify_merkle_proof(0, &wrong_leaf, &proof));
    }

    #[test]
    fn test_threshold_verify_native() {
        let (group, secret_keys, _) = make_test_group(4, 3);
        let message: [F; MESSAGE_LEN_FE] = std::array::from_fn(F::from_usize);

        let mut rng = StdRng::seed_from_u64(123);
        let signer_indices = vec![0, 1, 3]; // 3-of-4
        let xmss_signatures: Vec<XmssSignature> = signer_indices
            .iter()
            .map(|&i| xmss_sign(&mut rng, &secret_keys[i], &message, 1100).unwrap())
            .collect();

        let tsig = ThresholdSignature {
            signer_indices,
            xmss_signatures,
        };

        threshold_verify(&group, &tsig, &message).unwrap();
    }

    #[test]
    fn test_threshold_verify_below_threshold() {
        let (group, secret_keys, _) = make_test_group(4, 3);
        let message: [F; MESSAGE_LEN_FE] = std::array::from_fn(F::from_usize);

        let mut rng = StdRng::seed_from_u64(123);
        let signer_indices = vec![0, 1]; // only 2, threshold is 3
        let xmss_signatures: Vec<XmssSignature> = signer_indices
            .iter()
            .map(|&i| xmss_sign(&mut rng, &secret_keys[i], &message, 1100).unwrap())
            .collect();

        let tsig = ThresholdSignature {
            signer_indices,
            xmss_signatures,
        };

        assert_eq!(
            threshold_verify(&group, &tsig, &message),
            Err(ThresholdVerifyError::BelowThreshold)
        );
    }

    #[test]
    fn test_threshold_verify_duplicate_signer() {
        let (group, secret_keys, _) = make_test_group(4, 2);
        let message: [F; MESSAGE_LEN_FE] = std::array::from_fn(F::from_usize);

        let mut rng = StdRng::seed_from_u64(123);
        let sig0 = xmss_sign(&mut rng, &secret_keys[0], &message, 1100).unwrap();
        let sig0b = xmss_sign(&mut rng, &secret_keys[0], &message, 1100).unwrap();

        let tsig = ThresholdSignature {
            signer_indices: vec![0, 0],
            xmss_signatures: vec![sig0, sig0b],
        };

        assert_eq!(
            threshold_verify(&group, &tsig, &message),
            Err(ThresholdVerifyError::DuplicateSignerIndex)
        );
    }
}
