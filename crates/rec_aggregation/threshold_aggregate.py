from xmss_aggregate import *

MAX_THRESHOLD_GROUPS = MAX_THRESHOLD_GROUPS_PLACEHOLDER
MAX_THRESHOLD_DEPTH = MAX_THRESHOLD_DEPTH_PLACEHOLDER
MAX_THRESHOLD_SIGNERS = 2 ** MAX_THRESHOLD_DEPTH


@inline
def threshold_verify_group(all_pubkeys, threshold_data, message, slot_lo, slot_hi, merkle_chunks):
    # threshold_data layout:
    #   [k_actual | k_min | depth | global_pubkey_idx |
    #    r_G(DIGEST_LEN) | leaf_indices(k) | signer_merkle_roots(k*DIGEST_LEN) |
    #    xmss_sigs(k*SIG_SIZE) | hypertree_proofs(k*depth*DIGEST_LEN)]

    k = threshold_data[0]
    k_min = threshold_data[1]
    depth = threshold_data[2]
    global_pubkey_idx = threshold_data[3]

    assert 0 < k_min
    assert k_min <= k          # enforce minimum threshold
    assert k <= MAX_THRESHOLD_SIGNERS
    assert 0 < depth
    assert depth <= MAX_THRESHOLD_DEPTH

    # The registered joint public key commits to both the hypertree root r_G and
    # k_min: joint_key = poseidon16(r_G, [k_min, 0, ..., 0]).
    # Verify the r_G hint against the committed joint key so that k_min cannot
    # be forged independently of the registered public key.
    r_G_hint = threshold_data + 4
    k_min_tag = Array(DIGEST_LEN)
    k_min_tag[0] = k_min
    for j in unroll(1, DIGEST_LEN):
        k_min_tag[j] = 0
    expected_commitment = all_pubkeys + global_pubkey_idx * DIGEST_LEN
    computed_commitment = Array(DIGEST_LEN)
    poseidon16(r_G_hint, k_min_tag, computed_commitment)
    for j in unroll(0, DIGEST_LEN):
        assert computed_commitment[j] == expected_commitment[j]

    # Compute section pointers
    indices_ptr = threshold_data + 4 + DIGEST_LEN
    roots_ptr = indices_ptr + k
    sigs_ptr = roots_ptr + k * DIGEST_LEN
    proofs_ptr = sigs_ptr + k * SIG_SIZE

    # Distinctness enforcement via write-once memory:
    # Each iteration writes a unique value (i+1). If the same leaf_idx appears
    # twice, the second write has a different value → MemoryAlreadySet error.
    # The memory table (Logup) enforces this in the proof.
    seen = Array(MAX_THRESHOLD_SIGNERS)

    for i in range(0, k):
        leaf_idx = indices_ptr[i]

        # Leaf index valid and unique: must be within the actual tree width (2^depth),
        # not just the global MAX_THRESHOLD_SIGNERS bound.
        assert leaf_idx < powers_of_two(depth)
        seen[leaf_idx] = i + 1

        # Verify XMSS signature against signer's merkle root hint
        signer_root = roots_ptr + i * DIGEST_LEN
        sig = sigs_ptr + i * SIG_SIZE
        xmss_verify(signer_root, message, sig, slot_lo, slot_hi, merkle_chunks)

        # Verify signer's root is a leaf of the hypertree
        proof = proofs_ptr + i * depth * DIGEST_LEN
        computed_root = Array(DIGEST_LEN)
        hypertree_merkle_verify(signer_root, proof, leaf_idx, depth, computed_root)

        # Assert computed root matches the verified r_G hint
        for j in unroll(0, DIGEST_LEN):
            assert computed_root[j] == r_G_hint[j]

    return global_pubkey_idx


@inline
def hypertree_merkle_verify(leaf_digest, proof_path, leaf_idx, depth, out_root):
    match depth:
        case 1:
            _hypertree_verify_d1(leaf_digest, proof_path, leaf_idx, out_root)
        case 2:
            _hypertree_verify_d2(leaf_digest, proof_path, leaf_idx, out_root)
        case 3:
            _hypertree_verify_d3(leaf_digest, proof_path, leaf_idx, out_root)
    return


def _hypertree_verify_d1(leaf_digest, proof, leaf_idx, out_root):
    assert leaf_idx < 2
    match leaf_idx:
        case 0:
            poseidon16(leaf_digest, proof, out_root)
        case 1:
            poseidon16(proof, leaf_digest, out_root)
    return


def _hypertree_verify_d2(leaf_digest, proof, leaf_idx, out_root):
    # bits: BIG_ENDIAN, bits[0]=MSB, bits[1]=LSB
    bits = checked_decompose_bits_small_value_const(leaf_idx, 2)
    temp = Array(DIGEST_LEN)
    # Level 0: LSB = bits[1]
    match bits[1]:
        case 0:
            poseidon16(leaf_digest, proof, temp)
        case 1:
            poseidon16(proof, leaf_digest, temp)
    # Level 1: MSB = bits[0]
    match bits[0]:
        case 0:
            poseidon16(temp, proof + DIGEST_LEN, out_root)
        case 1:
            poseidon16(proof + DIGEST_LEN, temp, out_root)
    return


def _hypertree_verify_d3(leaf_digest, proof, leaf_idx, out_root):
    # bits: BIG_ENDIAN, bits[0]=MSB, bits[1]=mid, bits[2]=LSB
    bits = checked_decompose_bits_small_value_const(leaf_idx, 3)
    temp0 = Array(DIGEST_LEN)
    temp1 = Array(DIGEST_LEN)
    # Level 0: LSB = bits[2]
    match bits[2]:
        case 0:
            poseidon16(leaf_digest, proof, temp0)
        case 1:
            poseidon16(proof, leaf_digest, temp0)
    # Level 1: bits[1]
    match bits[1]:
        case 0:
            poseidon16(temp0, proof + DIGEST_LEN, temp1)
        case 1:
            poseidon16(proof + DIGEST_LEN, temp0, temp1)
    # Level 2: MSB = bits[0]
    match bits[0]:
        case 0:
            poseidon16(temp1, proof + 2 * DIGEST_LEN, out_root)
        case 1:
            poseidon16(proof + 2 * DIGEST_LEN, temp1, out_root)
    return
