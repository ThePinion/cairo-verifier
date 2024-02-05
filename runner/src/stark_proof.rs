use num_bigint::BigUint;

use crate::ast::{Expr, Exprs};

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct StarkProof {
    pub config: StarkConfig,
    pub unsent_commitment: StarkUnsentCommitment
}
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct StarkConfig {
    pub traces: TracesConfig,
    pub composition: TableCommitmentConfig,
    pub fri: FriConfig,
    pub proof_of_work: ProofOfWorkConfig,
    pub log_trace_domain_size: u32,
    pub n_queries: u32,
    pub log_n_cosets: u32,
    pub n_verifier_friendly_commitment_layers: u32,
}
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct TracesConfig {
    pub original: TableCommitmentConfig,
    pub interaction: TableCommitmentConfig,
}
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct TableCommitmentConfig {
    pub n_columns: u32,
    pub vector: VectorCommitmentConfig,
}
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct VectorCommitmentConfig {
    pub height: u32,
    pub n_verifier_friendly_commitment_layers: u32,
}
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct FriConfig {
    pub log_input_size: u32,
    pub n_layers: u32,
    // When deserialized this should skip first nesting. Flatten the TblCmmtmntCnfg
    pub inner_layers: Vec<TableCommitmentConfig>,
    pub fri_step_sizes: Vec<u32>,
    pub log_last_layer_degree_bound: u32,
}
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct ProofOfWorkConfig {
    pub n_bits: u32,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct StarkUnsentCommitment {
    pub traces: TracesUnsentCommitment,
    pub composition: BigUint,
    pub oods_values: Vec<BigUint>,
    pub fri: FriUnsentCommitment,
    pub proof_of_work: ProofOfWorkUnsentCommitment,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct TracesUnsentCommitment {
    pub original: BigUint,
    pub interaction: BigUint
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct FriUnsentCommitment {
    pub inner_layers: Vec<BigUint>,
    pub last_layer_coefficients: Vec<BigUint>
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct ProofOfWorkUnsentCommitment {
    pub nonce: BigUint
}

pub trait IntoAst {
    fn into_ast(self) -> Vec<Expr>;
}

impl IntoAst for u32 {
    fn into_ast(self) -> Vec<Expr> {
        vec![Expr::Value(format!("{self}"))]
    }
}

impl IntoAst for BigUint {
    fn into_ast(self) -> Vec<Expr> {
        vec![Expr::Value(format!("{self}"))]
    }
}

impl IntoAst for StarkProof {
    fn into_ast(self) -> Vec<Expr> {
        [self.config.into_ast(), self.unsent_commitment.into_ast()].concat()
    }
}

impl IntoAst for StarkConfig {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.traces.into_ast());
        exprs.append(&mut self.composition.into_ast());
        exprs.append(&mut self.fri.into_ast());
        exprs.append(&mut self.proof_of_work.into_ast());
        exprs.append(&mut self.log_trace_domain_size.into_ast());
        exprs.append(&mut self.n_queries.into_ast());
        exprs.append(&mut self.log_n_cosets.into_ast());
        exprs.append(&mut self.n_verifier_friendly_commitment_layers.into_ast());
        exprs
    }
}

impl IntoAst for TracesConfig {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.original.into_ast());
        exprs.append(&mut self.interaction.into_ast());
        exprs
    }
}

impl IntoAst for TableCommitmentConfig {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.n_columns.into_ast());
        exprs.append(&mut self.vector.into_ast());
        exprs
    }
}

impl IntoAst for VectorCommitmentConfig {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.height.into_ast());
        exprs.append(&mut self.n_verifier_friendly_commitment_layers.into_ast());
        exprs
    }
}

impl IntoAst for FriConfig {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.log_input_size.into_ast());
        exprs.append(&mut self.n_layers.into_ast());
        exprs.append(&mut self.inner_layers.into_ast());
        exprs.append(&mut self.fri_step_sizes.into_ast());
        exprs.append(&mut self.log_last_layer_degree_bound.into_ast());
        exprs
    }
}

impl IntoAst for StarkUnsentCommitment {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.traces.into_ast());
        exprs.append(&mut self.composition.into_ast());
        exprs.append(&mut self.oods_values.into_ast());
        exprs.append(&mut self.fri.into_ast());
        exprs.append(&mut self.proof_of_work.into_ast());
        exprs
    }
}

impl IntoAst for TracesUnsentCommitment {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.original.into_ast());
        exprs.append(&mut self.interaction.into_ast());
        exprs
    }
}

impl IntoAst for FriUnsentCommitment {
    fn into_ast(self) -> Vec<Expr> {
        let mut exprs = vec![];
        exprs.append(&mut self.inner_layers.into_ast());
        exprs.append(&mut self.last_layer_coefficients.into_ast());
        exprs
    }
}

impl IntoAst for ProofOfWorkUnsentCommitment {
    fn into_ast(self) -> Vec<Expr> {
        vec![Expr::Value(format!("{}", self.nonce))]
    }
}

impl IntoAst for ProofOfWorkConfig {
    fn into_ast(self) -> Vec<Expr> {
        vec![Expr::Value(format!("{}", self.n_bits))]
    }
}

impl <T> IntoAst for Vec<T> where T: IntoAst {
    fn into_ast(self) -> Vec<Expr> {
        vec![Expr::Array(self.into_iter().flat_map(|x| x.into_ast()).collect())]
    }
}

impl From<StarkProof> for Exprs {
    fn from(proof: StarkProof) -> Self {
        Exprs(proof.into_ast())
    }
}