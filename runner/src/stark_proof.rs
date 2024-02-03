#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct StarkProof {
    pub config: StarkConfig,
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
    pub vector: VectorCommitmentConfig
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