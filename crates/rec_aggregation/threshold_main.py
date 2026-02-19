from threshold_aggregate import *

N_INSTRUCTION_COLUMNS = N_INSTRUCTION_COLUMNS_PLACEHOLDER
LOG_GUEST_BYTECODE_LEN = LOG_GUEST_BYTECODE_LEN_PLACEHOLDER
BYTECODE_ZERO_EVAL = BYTECODE_ZERO_EVAL_PLACEHOLDER

BYTECODE_POINT_N_VARS = LOG_GUEST_BYTECODE_LEN + log2_ceil(N_INSTRUCTION_COLUMNS)

# Public input layout:
# [threshold_root(DIGEST_LEN) | minimum_k(1) | message(MESSAGE_LEN) | slot_lo | slot_hi |
#  merkle_chunks(N_MERKLE_CHUNKS) | bytecode_claim(BYTECODE_CLAIM_SIZE)]
# minimum_k is the policy threshold: the proof is only valid if at least minimum_k
# distinct members signed. It is public so that verifiers can enforce the group policy.
BYTECODE_CLAIM_OFFSET = DIGEST_LEN + 1 + MESSAGE_LEN + 2 + N_MERKLE_CHUNKS


def main():
    pub_mem = NONRESERVED_PROGRAM_INPUT_START
    minimum_k_ptr = pub_mem + DIGEST_LEN
    minimum_k = minimum_k_ptr[0]
    message = pub_mem + DIGEST_LEN + 1
    slot_ptr = message + MESSAGE_LEN
    slot_lo = slot_ptr[0]
    slot_hi = slot_ptr[1]
    merkle_chunks_for_slot = slot_ptr + 2
    bytecode_claim_output = pub_mem + BYTECODE_CLAIM_OFFSET

    priv_start: Imu
    hint_private_input_start(priv_start)

    # Private input layout:
    # [k | depth | global_pubkey_idx=0 | pub_input_root_ptr | leaf_indices(k) |
    #  signer_roots(k*DIGEST_LEN) | xmss_sigs(k*SIG_SIZE) | hypertree_proofs(k*depth*DIGEST_LEN)]
    #
    # pub_input_root_ptr (index 3) holds NONRESERVED_PROGRAM_INPUT_START as a runtime
    # value.  Loading it via array dereference makes it a Memory(Var(...)) in the
    # simplifier, which is the only form accepted by apply_to_var when the variable
    # is substituted into an ArrayAccess position inside @inline function bodies.
    # We assert equality with the compile-time constant to prevent the prover from
    # supplying a different address.
    threshold_data = priv_start
    k_actual = threshold_data[0]
    global_pubkey_idx = threshold_data[2]
    assert global_pubkey_idx == 0

    threshold_root = threshold_data[3]
    assert threshold_root == NONRESERVED_PROGRAM_INPUT_START

    threshold_verify_group_with_root(
        threshold_root, threshold_data, message, slot_lo, slot_hi, merkle_chunks_for_slot
    )

    # Enforce group policy: the number of verified signers must meet the minimum threshold
    assert minimum_k <= k_actual

    # Trivial bytecode claim (this circuit has no inner recursions)
    for ki in unroll(0, BYTECODE_POINT_N_VARS):
        set_to_5_zeros(bytecode_claim_output + ki * DIM)
    bytecode_claim_output[BYTECODE_POINT_N_VARS * DIM] = BYTECODE_ZERO_EVAL
    for ki in unroll(1, DIM):
        bytecode_claim_output[BYTECODE_POINT_N_VARS * DIM + ki] = 0
    return
