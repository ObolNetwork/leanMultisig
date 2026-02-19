from xmss_aggregate import *

MAX_THRESHOLD_GROUPS = MAX_THRESHOLD_GROUPS_PLACEHOLDER
MAX_THRESHOLD_DEPTH = MAX_THRESHOLD_DEPTH_PLACEHOLDER
MAX_THRESHOLD_SIGNERS = 2 ** MAX_THRESHOLD_DEPTH


@inline
def threshold_verify_group(all_pubkeys, threshold_data, message, slot_lo, slot_hi, merkle_chunks):
    # threshold_data layout:
    #   [k | depth | global_pubkey_idx |
    #    leaf_indices(k) | signer_merkle_roots(k*DIGEST_LEN) |
    #    xmss_sigs(k*SIG_SIZE) | hypertree_proofs(k*depth*DIGEST_LEN)]

    k = threshold_data[0]
    depth = threshold_data[1]
    global_pubkey_idx = threshold_data[2]

    assert 0 < k
    assert k <= MAX_THRESHOLD_SIGNERS
    assert 0 < depth
    assert depth <= MAX_THRESHOLD_DEPTH

    expected_root = all_pubkeys + global_pubkey_idx * DIGEST_LEN

    # Compute section pointers
    indices_ptr = threshold_data + 3
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

        # Assert computed root matches the group's expected root
        for j in unroll(0, DIGEST_LEN):
            assert computed_root[j] == expected_root[j]

    return global_pubkey_idx


def threshold_verify_group_with_root(expected_root, threshold_data, message, slot_lo, slot_hi, merkle_chunks):
    # Like threshold_verify_group but accepts expected_root directly instead of
    # computing it from (all_pubkeys, global_pubkey_idx).  expected_root must be a
    # Memory(Var(...)) in the simplifier — the caller is responsible for loading it
    # via a memory dereference (e.g. threshold_data[3]) rather than passing a
    # compile-time constant address.
    #
    # Private input layout consumed here:
    # [k(0) | depth(1) | global_pubkey_idx(2) | pub_input_root_ptr(3) |
    #  leaf_indices(k starting at 4) | signer_roots(k*DIGEST_LEN) |
    #  xmss_sigs(k*SIG_SIZE) | hypertree_proofs(k*depth*DIGEST_LEN)]
    k = threshold_data[0]
    depth = threshold_data[1]

    assert 0 < k
    assert k <= MAX_THRESHOLD_SIGNERS
    assert 0 < depth
    assert depth <= MAX_THRESHOLD_DEPTH

    indices_ptr = threshold_data + 4
    roots_ptr = indices_ptr + k
    sigs_ptr = roots_ptr + k * DIGEST_LEN
    proofs_ptr = sigs_ptr + k * SIG_SIZE

    seen = Array(MAX_THRESHOLD_SIGNERS)

    for i in range(0, k):
        leaf_idx = indices_ptr[i]

        assert leaf_idx < powers_of_two(depth)
        seen[leaf_idx] = i + 1

        signer_root = roots_ptr + i * DIGEST_LEN
        sig = sigs_ptr + i * SIG_SIZE
        xmss_verify(signer_root, message, sig, slot_lo, slot_hi, merkle_chunks)

        proof = proofs_ptr + i * depth * DIGEST_LEN
        computed_root = Array(DIGEST_LEN)
        hypertree_merkle_verify(signer_root, proof, leaf_idx, depth, computed_root)

        for j in unroll(0, DIGEST_LEN):
            assert computed_root[j] == expected_root[j]

    return


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
