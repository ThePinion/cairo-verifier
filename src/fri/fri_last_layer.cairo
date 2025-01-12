use cairo_verifier::{common::{horner_eval, math::Felt252Div}, fri::fri_layer::FriLayerQuery,};

// Verifies FRI last layer by evaluating the given polynomial on the given points
// (=inverses of x_inv_values), and comparing the results to the given values.
fn verify_last_layer(queries: Span<FriLayerQuery>, coefficients: Span<felt252>) {
    let mut i: u32 = 0;
    let len: u32 = queries.len();
    loop {
        if i == len {
            break;
        }
        let value = horner_eval::horner_eval(coefficients, 1 / *queries.at(i).x_inv_value);
        assert(value == *queries.at(i).y_value, 'Invalid value');
        i += 1;
    }
}
