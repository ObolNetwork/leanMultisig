use backend::*;

pub use backend::ProofError;
pub use rec_aggregation::{AggregatedXMSS, AggregationTopology, xmss_aggregate, xmss_verify_aggregation};
pub use xmss::{MESSAGE_LEN_FE, XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen, xmss_sign, xmss_verify};

pub type F = KoalaBear;

/// Call once before proving. Compiles the aggregation program and precomputes DFT twiddles.
pub fn setup_prover() {
    rec_aggregation::compilation::init_aggregation_bytecode();
    precompute_dft_twiddles::<F>(1 << 24);
}

/// Call once before verifying (not needed if `setup_prover` was already called).
pub fn setup_verifier() {
    rec_aggregation::compilation::init_aggregation_bytecode();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use xmss::hypertree::{ThresholdGroup, ThresholdSignature};
    use xmss::signers_cache::{
        BENCHMARK_SLOT, find_randomness_for_benchmark, message_for_benchmark, reconstruct_signer_for_benchmark,
    };

    fn make_threshold_group(
        k: usize,
        n: usize,
        message: &[F; MESSAGE_LEN_FE],
        slot: u32,
        seed: u64,
    ) -> (ThresholdGroup, ThresholdSignature) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut roots = Vec::new();
        let mut secret_keys = Vec::new();
        for _ in 0..n {
            let seed: [u8; 32] = rand::Rng::random(&mut rng);
            let (sk, pk) = xmss_key_gen(seed, slot.saturating_sub(2), slot + 2).unwrap();
            roots.push(pk.merkle_root);
            secret_keys.push(sk);
        }
        let group = ThresholdGroup::new(k, &roots);

        let signer_indices: Vec<usize> = (0..k).collect();
        let xmss_signatures: Vec<_> = signer_indices
            .iter()
            .map(|&i| xmss_sign(&mut rng, &secret_keys[i], message, slot).unwrap())
            .collect();

        let merkle_proofs: Vec<_> = signer_indices.iter().map(|&i| group.merkle_proof(i)).collect();
        let tsig = ThresholdSignature {
            signer_indices,
            xmss_signatures,
            merkle_proofs,
        };
        (group, tsig)
    }

    #[test]
    fn test_xmss_signature() {
        let start = 555;
        let end = 565;
        let slot = 560;
        let key_gen_seed: [u8; 20] = rand::rng().random();
        let message_hash: [F; MESSAGE_LEN_FE] = std::array::from_fn(|i| F::from_usize(i * 3));

        let (secret_key, pub_key) = xmss_key_gen(key_gen_seed, start, end).unwrap();
        let signature = xmss_sign(&mut rand::rng(), &secret_key, &message_hash, slot).unwrap();
        xmss_verify(&pub_key, &message_hash, &signature).unwrap();
    }

    #[test]
    fn test_recursive_aggregation() {
        setup_prover();

        let log_inv_rate = 2; // [1, 2, 3 or 4] (lower = faster but bigger proofs)
        let message: [F; MESSAGE_LEN_FE] = message_for_benchmark();
        let slot: u32 = BENCHMARK_SLOT;

        let pub_keys_and_sigs_a: Vec<_> = (0..3)
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();
        let aggregated_a = xmss_aggregate(&[], pub_keys_and_sigs_a, &[], &message, slot, log_inv_rate);

        let pub_keys_and_sigs_b: Vec<_> = (3..5)
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();
        let aggregated_b = xmss_aggregate(&[], pub_keys_and_sigs_b, &[], &message, slot, log_inv_rate);

        let pub_keys_and_sigs_c: Vec<_> = (5..6)
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();

        let aggregated_final = xmss_aggregate(
            &[aggregated_a, aggregated_b],
            pub_keys_and_sigs_c,
            &[],
            &message,
            slot,
            log_inv_rate,
        );

        let serialized_final = aggregated_final.serialize();
        println!("Serialized aggregated final: {} KiB", serialized_final.len() / 1024);
        let deserialized_final = AggregatedXMSS::deserialize(&serialized_final).unwrap();

        xmss_verify_aggregation(&deserialized_final, &message, slot).unwrap();
    }

    #[test]
    fn test_mixed_threshold_aggregation() {
        setup_prover();

        let log_inv_rate = 1;
        let prox_gaps_conjecture = false;
        let message: [F; MESSAGE_LEN_FE] = message_for_benchmark();
        let slot: u32 = BENCHMARK_SLOT;

        // 2 raw XMSS signers
        let raw_xmss: Vec<_> = (0..2)
            .into_par_iter()
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();

        // 1 threshold group (2-of-3)
        let threshold = make_threshold_group(2, 3, &message, slot, 42);

        let aggregated = aggregate(
            &[],
            raw_xmss,
            &[threshold],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        verify_aggregation(&aggregated, &message, slot, prox_gaps_conjecture).unwrap();
    }

    #[test]
    fn test_recursive_threshold_aggregation() {
        setup_prover();

        let log_inv_rate = 1;
        let prox_gaps_conjecture = false;
        let message: [F; MESSAGE_LEN_FE] = message_for_benchmark();
        let slot: u32 = BENCHMARK_SLOT;

        // Child A: 2 raw XMSS, no threshold
        let raw_xmss_a: Vec<_> = (0..2)
            .into_par_iter()
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();
        let child_a = aggregate(
            &[],
            raw_xmss_a,
            &[],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        // Child B: 1 raw XMSS + 1 threshold group (2-of-3)
        // (recursive children need >= 2 pubkeys for the in-circuit hash initialization)
        let raw_xmss_b: Vec<_> = (2..3)
            .into_par_iter()
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();
        let threshold = make_threshold_group(2, 3, &message, slot, 42);
        let child_b = aggregate(
            &[],
            raw_xmss_b,
            &[threshold],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        // Parent: aggregates children A and B + 1 additional raw XMSS (index 3)
        let raw_xmss_parent: Vec<_> = (3..4)
            .into_par_iter()
            .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
            .collect();
        let parent = aggregate(
            &[child_a, child_b],
            raw_xmss_parent,
            &[],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        verify_aggregation(&parent, &message, slot, prox_gaps_conjecture).unwrap();
    }

    /// 3-level aggregation tree with threshold groups at every level:
    ///
    /// ```text
    ///                            Root
    ///                       2 raw + T(2/3)
    ///                      /               \
    ///                Mid-A                  Mid-B
    ///             2 raw XMSS          2 raw + T(2/4)
    ///             /        \                 |
    ///       Leaf-A1      Leaf-A2          Leaf-B1
    ///     3 raw XMSS   2 raw + T(2/3)   3 raw XMSS
    /// ```
    #[test]
    fn test_fancy_threshold_aggregation() {
        setup_prover();

        let log_inv_rate = 1;
        let prox_gaps_conjecture = false;
        let message: [F; MESSAGE_LEN_FE] = message_for_benchmark();
        let slot: u32 = BENCHMARK_SLOT;

        let raw = |range: std::ops::Range<usize>| -> Vec<(XmssPublicKey, XmssSignature)> {
            range
                .into_par_iter()
                .map(|i| reconstruct_signer_for_benchmark(i, find_randomness_for_benchmark(i)))
                .collect()
        };

        // ── Leaf level ──

        // Leaf-A1: 3 raw XMSS (indices 0..3)
        let leaf_a1 = aggregate(&[], raw(0..3), &[], &message, slot, log_inv_rate, prox_gaps_conjecture);

        // Leaf-A2: 2 raw XMSS (indices 3..5) + T(2/3)
        let leaf_a2 = aggregate(
            &[],
            raw(3..5),
            &[make_threshold_group(2, 3, &message, slot, 100)],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        // Leaf-B1: 3 raw XMSS (indices 5..8)
        let leaf_b1 = aggregate(&[], raw(5..8), &[], &message, slot, log_inv_rate, prox_gaps_conjecture);

        // ── Mid level ──

        // Mid-A: recurse [Leaf-A1, Leaf-A2] + 2 raw XMSS (indices 8..10)
        let mid_a = aggregate(
            &[leaf_a1, leaf_a2],
            raw(8..10),
            &[],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        // Mid-B: recurse [Leaf-B1] + 2 raw XMSS (indices 10..12) + T(2/4)
        let mid_b = aggregate(
            &[leaf_b1],
            raw(10..12),
            &[make_threshold_group(2, 4, &message, slot, 200)],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        // ── Root level ──

        // Root: recurse [Mid-A, Mid-B] + 2 raw XMSS (indices 12..14) + T(2/3)
        let root = aggregate(
            &[mid_a, mid_b],
            raw(12..14),
            &[make_threshold_group(2, 3, &message, slot, 300)],
            &message,
            slot,
            log_inv_rate,
            prox_gaps_conjecture,
        );

        verify_aggregation(&root, &message, slot, prox_gaps_conjecture).unwrap();
    }
}
