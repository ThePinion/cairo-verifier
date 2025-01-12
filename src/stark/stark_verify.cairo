use cairo_verifier::{
    queries::queries::queries_to_points, domains::StarkDomains,
    fri::fri::{FriDecommitment, fri_verify},
    stark::{StarkUnsentCommitment, StarkWitness, StarkCommitment}, air::traces::traces_decommit,
    table_commitment::table_commitment::table_decommit,
    oods::{OodsEvaluationInfo, eval_oods_boundary_poly_at_points},
};

// STARK verify phase.
fn stark_verify(
    n_original_columns: u32,
    n_interaction_columns: u32,
    queries: Span<felt252>,
    commitment: StarkCommitment,
    witness: StarkWitness,
    stark_domains: StarkDomains,
) {
    // First layer decommit.
    traces_decommit(
        queries, commitment.traces, witness.traces_decommitment, witness.traces_witness
    );

    table_decommit(
        commitment.composition,
        queries,
        witness.composition_decommitment,
        witness.composition_witness,
    );

    // Compute query points.
    let points = queries_to_points(queries, @stark_domains);

    // Evaluate the FRI input layer at query points.
    let eval_info = OodsEvaluationInfo {
        oods_values: commitment.oods_values,
        oods_point: commitment.interaction_after_composition,
        trace_generator: stark_domains.trace_generator,
        constraint_coefficients: commitment.interaction_after_oods,
    };
    let oods_poly_evals = eval_oods_boundary_poly_at_points(
        n_original_columns,
        n_interaction_columns,
        eval_info,
        points.span(),
        witness.traces_decommitment,
        witness.composition_decommitment,
    );

    // Decommit FRI.
    let fri_decommitment = FriDecommitment {
        values: oods_poly_evals.span(), points: points.span(),
    };
    fri_verify(
        queries: queries,
        commitment: commitment.fri,
        decommitment: fri_decommitment,
        witness: witness.fri_witness,
    )
}
