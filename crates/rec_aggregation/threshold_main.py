from threshold_aggregate import *

N_INSTRUCTION_COLUMNS = N_INSTRUCTION_COLUMNS_PLACEHOLDER
LOG_GUEST_BYTECODE_LEN = LOG_GUEST_BYTECODE_LEN_PLACEHOLDER
BYTECODE_ZERO_EVAL = BYTECODE_ZERO_EVAL_PLACEHOLDER

BYTECODE_POINT_N_VARS = LOG_GUEST_BYTECODE_LEN + log2_ceil(N_INSTRUCTION_COLUMNS)

# Public input layout:
# [threshold_root(DIGEST_LEN) | message(MESSAGE_LEN) | slot_lo | slot_hi |
#  merkle_chunks(N_MERKLE_CHUNKS) | bytecode_claim(BYTECODE_CLAIM_SIZE)]
BYTECODE_CLAIM_OFFSET = DIGEST_LEN + MESSAGE_LEN + 2 + N_MERKLE_CHUNKS


def main():
    pub_mem = NONRESERVED_PROGRAM_INPUT_START
    threshold_root = pub_mem
    message = threshold_root + DIGEST_LEN
    slot_ptr = message + MESSAGE_LEN
    slot_lo = slot_ptr[0]
    slot_hi = slot_ptr[1]
    merkle_chunks_for_slot = slot_ptr + 2
    bytecode_claim_output = pub_mem + BYTECODE_CLAIM_OFFSET

    priv_start: Imu
    hint_private_input_start(priv_start)

    # Private input layout:
    # [k | depth | 0 | leaf_indices(k) | signer_roots(k*DIGEST_LEN) |
    #  xmss_sigs(k*SIG_SIZE) | hypertree_proofs(k*depth*DIGEST_LEN)]
    # global_pubkey_idx is always 0 (single pubkey = the threshold root)
    threshold_data = priv_start

    global_idx = threshold_verify_group(
        threshold_root, threshold_data, message, slot_lo, slot_hi, merkle_chunks_for_slot
    )
    assert global_idx == 0

    # Trivial bytecode claim (this circuit has no inner recursions)
    for k in unroll(0, BYTECODE_POINT_N_VARS):
        set_to_5_zeros(bytecode_claim_output + k * DIM)
    bytecode_claim_output[BYTECODE_POINT_N_VARS * DIM] = BYTECODE_ZERO_EVAL
    for k in unroll(1, DIM):
        bytecode_claim_output[BYTECODE_POINT_N_VARS * DIM + k] = 0
    return
