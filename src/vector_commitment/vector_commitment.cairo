use cairo_verifier::common::flip_endianness::FlipEndiannessTrait;
use cairo_verifier::common::{array_append::ArrayAppendTrait, blake2s::blake2s, math::pow};
use poseidon::hades_permutation;
// TODO: remove
use core::debug::PrintTrait;

// Commitment for a vector of field elements.
#[derive(Drop, Copy)]
struct VectorCommitment {
    config: VectorCommitmentConfig,
    commitment_hash: felt252
}

#[derive(Drop, Copy)]
struct VectorCommitmentConfig {
    height: felt252,
    n_verifier_friendly_commitment_layers: felt252,
}

// A query to the vector commitment.
#[derive(Drop, Copy)]
struct VectorQuery {
    index: felt252,
    value: felt252,
}

// A query to the vector commitment that contains also the depth of the query in the Merkle tree.
#[derive(Drop, Copy)]
struct VectorQueryWithDepth {
    index: felt252,
    value: felt252,
    depth: felt252,
}

// Witness for a decommitment over queries.
#[derive(Drop, Copy)]
struct VectorCommitmentWitness {
    // The authentication values: all the siblings of the subtree generated by the queried indices,
    // bottom layer up, left to right.
    authentications: Span<felt252>,
}

fn validate_vector_commitment(
    config: VectorCommitmentConfig,
    expected_height: felt252,
    n_verifier_friendly_commitment_layers: felt252,
) {
    assert(false, 'not implemented');
}

fn vector_commitment_decommit(
    commitment: VectorCommitment,
    n_queries: felt252,
    queries: Array<VectorQuery>,
    witness: VectorCommitmentWitness,
) {
    let shift = pow(2, commitment.config.height);
    let shifted_queries = shift_queries(queries.span(), shift, commitment.config.height);

    let root = compute_root_from_queries(shifted_queries, 0, commitment.config.n_verifier_friendly_commitment_layers, witness.authentications, 0);
    root.print();
}

// TODO: move to another file 
fn div_rem2(x: felt252) -> (felt252, felt252) {
    let x: u256 = x.into();
    let x_div = x / 2;
    let x_rem = x % 2;
    let x_div: felt252 = x_div.try_into().unwrap();
    let x_rem: felt252 = x_rem.try_into().unwrap();
    (x_div, x_rem)
}

// TODO: refactor
fn is_ge(x: felt252, y: felt252) -> bool {
    let x: u256 = x.into();
    let y: u256 = y.into();
    x >= y
}

fn compute_root_from_queries(
    mut queue: Array<VectorQueryWithDepth>,
    start: u32,
    n_verifier_friendly_layers: felt252,
    authentications: Span<felt252>,
    auth_start: u32
) -> felt252 {
    let current: VectorQueryWithDepth = *queue[start];

    if current.index == 1 { // root
        assert(current.depth == 0, 'root depth must be 0');
        assert(start + 1 == queue.len(), 'root must be the last element');
        return current.value;
    }

    let (parent, bit) = div_rem2(current.index);
    let is_verifier_friendly = is_ge(n_verifier_friendly_layers, current.depth);
    let hash = if bit == 0 {
        if start + 1 != queue.len() {
            let next: VectorQueryWithDepth = *queue[start + 1];
            if current.index + 1 == next.index {
                // next is a sibling of current
                let hash = hash_blake_or_poseidon(current.value, next.value, is_verifier_friendly);
                queue
                    .append(
                        VectorQueryWithDepth {
                            index: parent, value: hash, depth: current.depth - 1,
                        }
                    );
                return compute_root_from_queries(
                    queue, start + 2, n_verifier_friendly_layers, authentications, auth_start
                );
            }
        }
        hash_blake_or_poseidon(current.value, *authentications[auth_start], is_verifier_friendly)
    } else {
        hash_blake_or_poseidon(*authentications[auth_start], current.value, is_verifier_friendly)
    };
    queue.append(VectorQueryWithDepth { index: parent, value: hash, depth: current.depth - 1, });
    compute_root_from_queries(
        queue, start + 1, n_verifier_friendly_layers, authentications, auth_start + 1
    )
}

fn shift_queries(
    queries: Span<VectorQuery>, shift: felt252, height: felt252
) -> Array<VectorQueryWithDepth> {
    let mut shifted_queries = ArrayTrait::new();
    let mut i = 0;
    loop {
        if i == queries.len() {
            break;
        };
        let q = *queries[i];
        shifted_queries
            .append(
                VectorQueryWithDepth { index: q.index + shift, value: q.value, depth: height, }
            );
        i += 1;
    };
    shifted_queries
}

fn hash_blake_or_poseidon(x: felt252, y: felt252, is_verifier_friendly: bool) -> felt252 {
    if is_verifier_friendly {
        let (hash, _, _) = hades_permutation(x, y, 2);
        hash
    } else {
        truncated_blake2s(x, y)
    }
}

fn truncated_blake2s(x: felt252, y: felt252) -> felt252 {
    let mut data = ArrayTrait::<u32>::new();
    data.append_big_endian(x);
    data.append_big_endian(y);
    let hash = blake2s(data).flip_endianness() % 0x10000000000000000000000000000000000000000;
    hash.try_into().unwrap()
}
