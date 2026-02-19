# Threshold XMSS Aggregation

## Overview

Threshold XMSS adds k-of-n multisignature support to the zkVM aggregation system. A **threshold group** is a small set of up to 8 XMSS signers (e.g., 3-of-5 or 5-of-7) whose joint identity is represented by the root of a binary Merkle tree (the "hypertree") over their individual XMSS public keys.

This feature targets Distributed Validator (DV) clusters for Post-Quantum Ethereum, where a small group of operators must collectively authorize an action.

## Design Rationale

### Single-bytecode embedding

The central design decision is to embed threshold verification **inside the existing aggregation circuit** as a new source type, alongside raw XMSS signatures and recursive child proofs. This means:

- **One bytecode program** — The DSL circuit (`main.py`) remains a single compilation unit. Threshold groups are processed in a loop between the raw XMSS loop and the recursion loop.
- **Homogeneous recursion** — A parent aggregation node sees the output of a threshold-bearing proof as a standard `AggregatedSigs`. It does not need to know whether that child used thresholds, raw XMSS, or both. The bytecode claim reduction, public input format, and WHIR/Logup/AIR stack are untouched.
- **No new proof types** — There is no separate "threshold proof" artifact. The threshold verification is simply additional constraint logic inside the same proving pipeline.

The alternative would have been a separate threshold circuit producing its own proof, then fed as a child into recursive aggregation. That approach would double the proof overhead for simple threshold groups and require managing a second bytecode program and its compilation.

### Hypertree structure

The hypertree is a standard binary Merkle tree of depth `ceil(log2(n))`, where:
- Leaves are the individual XMSS `merkle_root` values (each 8 KoalaBear field elements).
- Non-leaf nodes are computed with `poseidon16_compress_pair(left, right)`, the same Poseidon2-based compression used throughout the codebase.
- If n is not a power of 2, the remaining leaves are padded with zero digests.
- The hypertree root serves as the threshold group's public key — a single 8-element digest that appears in the global `pub_keys` list.

Depth is capped at 3 (supporting groups of up to 8 members). This small bound allows the in-circuit Merkle verification to dispatch on depth statically (`match depth: case 1/2/3`), avoiding a general-purpose variable-depth loop in the DSL.

### In-circuit verification strategy

For each threshold group, the circuit verifies k participants:
1. **XMSS signature check** — Each signer's XMSS signature is verified against their individual `merkle_root`, using the same `xmss_verify` function used for raw XMSS signatures.
2. **Hypertree membership proof** — Each signer's `merkle_root` is proven to be a leaf of the hypertree via a Merkle path (1–3 sibling digests, depending on depth).
3. **Distinctness enforcement** — A bitmap array (`seen[MAX_THRESHOLD_SIGNERS]`) ensures no signer index is used twice.

The signer `merkle_root` values are provided as hints in the private input. The `xmss_verify` function writes the computed XMSS root to this hint location (the standard "write-to-pointer" assertion pattern in the DSL). Then `hypertree_merkle_verify` computes a fresh root from that same value and the Merkle path, and the circuit explicitly asserts element-wise equality between the computed hypertree root and the expected root from `all_pubkeys`.

## Architecture

### File layout

```
crates/xmss/src/
  hypertree.rs          NEW   Hypertree construction, Merkle proofs, native verification

crates/rec_aggregation/
  threshold_aggregate.py NEW   In-circuit threshold verification (DSL)
  main.py                MOD   Main circuit: added threshold loop, shifted header
  src/lib.rs             MOD   Rust aggregate(): threshold source blocks, Poseidon traces
  src/compilation.rs     MOD   Placeholder constants for threshold params
  src/benchmark.rs       MOD   Test data generation, display support

src/main.rs              MOD   CLI: added `threshold` subcommand
```

### Private input layout

The header was extended from the pre-threshold format to include a `n_threshold` count and threshold source pointers:

```
Pre-threshold:   [n_recursions | n_dup | ptr_pubkeys | ptr_src_0 | ptr_rec_0..n | ptr_bytecode_sumcheck]
Post-threshold:  [n_recursions | n_threshold | n_dup | ptr_pubkeys | ptr_src_0 | ptr_thresh_0..t | ptr_rec_0..n | ptr_bytecode_sumcheck]
```

Each threshold source block in private memory:
```
[k | depth | global_pubkey_idx | leaf_indices(k) | signer_roots(k*8) | xmss_sigs(k*SIG_SIZE) | hypertree_proofs(k*depth*8)]
```

### Topology integration

`AggregationTopology` gained a `threshold_groups: Vec<ThresholdGroupSpec>` field. Each `ThresholdGroupSpec { k, n }` contributes exactly 1 entry to the global public key set (the hypertree root). The `count_signers` function reflects this:

```rust
topology.raw_xmss + topology.threshold_groups.len() + child_count - overlap * n_overlaps
```

This means a topology node can freely mix raw XMSS, threshold groups, and recursive children. For example:

```rust
AggregationTopology {
    raw_xmss: 10,
    threshold_groups: vec![ThresholdGroupSpec { k: 3, n: 5 }],
    children: vec![some_child_topology],
    log_inv_rate: 1,
}
```

## Implications on Existing Code

### Changes that are backward-compatible

- All pre-existing `AggregationTopology` constructions simply set `threshold_groups: vec![]` and behave identically to before.
- The `aggregate()` function accepts `threshold_sigs: &[]` for no-threshold calls; the circuit's `n_threshold = 0` path adds zero overhead beyond reading and asserting the count.
- The public input format (`AggregatedSigs::public_input`) is unchanged. The bytecode claim reduction is unchanged. Verification (`verify_aggregation`) is unchanged.

### Changes that affect the circuit

- **Bytecode size increased** — The `threshold_aggregate.py` import adds new instructions to the compiled bytecode. The self-referential compilation loop handles this automatically (it re-converges on the correct `log_size`), but the bytecode is now larger, which means slightly more work for every proof — even those not using thresholds. In practice, the added instructions are small relative to the recursion verification logic.
- **Private input header shifted** — The `n_threshold` field was inserted at position `[1]`, pushing `n_dup` from `[1]` to `[2]` and `all_pubkeys` from `[2]` to `[3]`. This is a breaking change to the private input format. Any external tooling that constructs private inputs directly (rather than going through `aggregate()`) must be updated.
- **New compilation placeholders** — `MAX_THRESHOLD_DEPTH_PLACEHOLDER` and `MAX_THRESHOLD_GROUPS_PLACEHOLDER` are injected at compile time. These are consumed by `threshold_aggregate.py` and do not interact with any existing placeholder.

The alternative would have been a separate threshold circuit producing its own proof, then fed as a child into recursive aggregation. That approach would double the proof overhead for simple threshold groups and require managing a second bytecode program and its compilation. The `inline-vs-recursive-threshold` benchmark quantitatively demonstrates this, showing that using a recursive child proof for a threshold group introduces significant overhead (the `t_parent` cost) compared to embedding the verification directly. This confirms that the single-bytecode embedding strategy is substantially more efficient for this particular use case.

### Poseidon precomputation

The prover precomputes Poseidon2 hash traces to populate the Poseidon16 AIR table. The `precompute_poseidons` function was extended to include threshold traces via `threshold_verify_with_poseidon_trace()`. Each threshold signer contributes:
- All Poseidon hashes from their XMSS signature verification (WOTS chains + XMSS Merkle tree).
- `depth` additional Poseidon hashes for the hypertree Merkle path.

These are computed in parallel using Rayon.

## DSL Circuit Details

### Bit decomposition convention

The DSL's `checked_decompose_bits_small_value_const(value, n_bits)` uses **big-endian** ordering: `bits[0]` is the MSB and `bits[n-1]` is the LSB. For the hypertree Merkle verification at tree level `j` (bottom-up, starting from the leaves), the relevant bit is `bits[depth - 1 - j]`:

| Level j | Bit index (big-endian) | Meaning |
|---------|----------------------|---------|
| 0 (leaves) | `bits[depth-1]` = LSB | Left (0) or right (1) child at bottom |
| 1 | `bits[depth-2]` | Left or right at next level |
| depth-1 (root's children) | `bits[0]` = MSB | Left or right at top level |

### Hash ordering

Bit = 0 means even leaf index (left child): `poseidon16(current, sibling, output)`.
Bit = 1 means odd leaf index (right child): `poseidon16(sibling, current, output)`.

This is consistent with the Rust-side `verify_merkle_proof` and the existing XMSS Merkle verification in `xmss_aggregate.py`.

### Depth dispatch

Rather than a general variable-depth loop, the circuit dispatches statically:

```python
match depth:
    case 1: _hypertree_verify_d1(...)
    case 2: _hypertree_verify_d2(...)
    case 3: _hypertree_verify_d3(...)
```

Each case is a compile-time-known chain of Poseidon hashes with `match` on the bit values. This avoids dynamic loop bounds and is efficient for the small depth range.

### Root assertion pattern

Unlike the XMSS Merkle verification (which writes the computed root into the `expected_root` pointer location, relying on the memory-write-once property for assertion), the hypertree verification computes the root into a **fresh buffer** and then explicitly asserts equality:

```python
computed_root = Array(DIGEST_LEN)
hypertree_merkle_verify(signer_root, proof, leaf_idx, depth, computed_root)
for j in unroll(0, DIGEST_LEN):
    assert computed_root[j] == expected_root[j]
```

This is because `expected_root` points into the `all_pubkeys` region of private memory, which may already be written to. The explicit assertion is always safe regardless of memory state.

## Constants and Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_HYPERTREE_DEPTH` | 3 | Maximum depth of the binary Merkle tree |
| `MAX_HYPERTREE_LEAVES` | 8 | Maximum members per threshold group (2^3) |
| `MAX_THRESHOLD_GROUPS` | 100 | Maximum threshold groups per aggregation node |
| `MAX_THRESHOLD_SIGNERS` | 8 | Maximum k (signers) per group (= MAX_HYPERTREE_LEAVES) |

## Testing

### Integration tests (`cargo test --release --all`)

The existing `test_recursive_aggregation` in `src/lib.rs` passes with `threshold_sigs: &[]`, confirming backward compatibility.

### CLI benchmark

The `fancy-threshold-aggregation` command runs an end-to-end benchmark for complex, multi-layer aggregation topologies that include threshold groups.
`cargo run --release -- fancy-threshold-aggregation` tests the integration of threshold groups within a hierarchical aggregation structure, simulating more realistic deployment scenarios.
It simply consists of adapting `fancy-aggregation` to support threshold signatures.

## Future Potential Improvements

### Larger group sizes

The current `MAX_HYPERTREE_DEPTH = 3` limits groups to 8 members. Increasing to depth 4 (16 members) or depth 5 (32 members) requires:
1. Adding `_hypertree_verify_d4` / `_hypertree_verify_d5` cases to `threshold_aggregate.py`.
2. Updating `MAX_HYPERTREE_DEPTH` in `hypertree.rs`.
3. No other changes — the Rust-side private input construction and compilation are parameterized.

For much larger groups, the static `match depth` dispatch becomes unwieldy. A general-purpose `dynamic_unroll`-based Merkle loop (similar to the existing XMSS Merkle verification pattern with `match_range`) could replace the depth-dispatch approach, at the cost of slightly more bytecode.

### Weighted thresholds

The current design treats all members equally (each contributes 1 toward the threshold k). Weighted thresholds (where different members have different voting power) could be supported by:
- Assigning weights to each leaf in the hypertree.
- Accumulating weight instead of count in the circuit.
- Asserting accumulated weight >= threshold.

This would require minimal structural changes but adds arithmetic to the circuit loop.

### Threshold-of-thresholds

Since each threshold group produces a standard `AggregatedSigs` with a single hypertree root as its public key, a parent aggregation could include multiple threshold groups as raw public keys, and a higher-level threshold group could be built over those roots. This creates a recursive threshold structure without any new code — it is already supported by the topology system.

### Parallel threshold group proving

When multiple threshold groups appear in a single aggregation node, their XMSS verifications and hypertree proofs are independent. The circuit processes them sequentially (in the `for t_idx in range(0, n_threshold):` loop), but the Poseidon precomputation is already parallelized. If circuit-level parallelism becomes available, the threshold groups could be proven concurrently.

### Removing the k <= 8 constraint on signers per group

The distinctness check currently uses a bitmap of size `MAX_THRESHOLD_SIGNERS = 8`. Supporting larger k (while keeping n <= 8) is already handled, but if both k and n grow, the bitmap and pairwise-comparison strategies need scaling. A sorting-based approach or hash set could replace the bitmap for larger groups.
