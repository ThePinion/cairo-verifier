use serde::Deserialize;

use crate::{
    annotations::Annotations,
    layout::Layout,
    stark_proof::{
        FriConfig, FriLayerWitness, FriUnsentCommitment, FriWitness, ProofOfWorkConfig, ProofOfWorkUnsentCommitment, StarkConfig, StarkProof, StarkUnsentCommitment, StarkWitness, TableCommitmentConfig, TableCommitmentWitness, TableDecommitment, TracesConfig, TracesDecommitment, TracesUnsentCommitment, TracesWitness, VectorCommitmentConfig, VectorCommitmentWitness
    },
    utils::log2_if_power_of_2,
};

#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ProofJSON {
    proof_parameters: ProofParameters,
    annotations: Vec<String>,
    public_input: PublicInput,
}

#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ProofParameters {
    pub stark: Stark,
    #[serde(default)]
    pub n_verifier_friendly_commitment_layers: u32,
}

#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct Stark {
    pub fri: Fri,
    pub log_n_cosets: u32,
}

#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct Fri {
    pub fri_step_list: Vec<u32>,
    pub last_layer_degree_bound: u32,
    pub n_queries: u32,
    pub proof_of_work_bits: u32,
}

#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct PublicInput {
    pub layout: Layout,
    //TODO: Add dynamic params
    // pub dynamic_params: Option<DynamicParams>,
    n_steps: u32,
}

impl ProofJSON {
    const COMPONENT_HEIGHT: u32 = 16;
    pub fn stark_config(&self) -> anyhow::Result<StarkConfig> {
        let stark = &self.proof_parameters.stark;
        let n_verifier_friendly_commitment_layers =
            self.proof_parameters.n_verifier_friendly_commitment_layers;
        let consts = self.public_input.layout.get_consts();

        let log_eval_domain_size = self.log_eval_damain_size()?;
        let traces = TracesConfig {
            original: TableCommitmentConfig {
                n_columns: consts.num_columns_first,
                vector: VectorCommitmentConfig {
                    height: log_eval_domain_size,
                    n_verifier_friendly_commitment_layers: n_verifier_friendly_commitment_layers,
                },
            },
            interaction: TableCommitmentConfig {
                n_columns: consts.num_columns_second,
                vector: VectorCommitmentConfig {
                    height: log_eval_domain_size,
                    n_verifier_friendly_commitment_layers: n_verifier_friendly_commitment_layers,
                },
            },
        };

        let composition = TableCommitmentConfig {
            n_columns: consts.constraint_degree,
            vector: VectorCommitmentConfig {
                height: log_eval_domain_size,
                n_verifier_friendly_commitment_layers: n_verifier_friendly_commitment_layers,
            },
        };

        let fri = self.proof_parameters.stark.fri.clone();

        let proof_of_work = ProofOfWorkConfig {
            n_bits: fri.proof_of_work_bits,
        };
        let n_queries = fri.n_queries;

        let layer_log_sizes = self.layer_log_sizes()?;

        let fri_step_list = fri.fri_step_list;
        let log_last_layer_degree_bound = log2_if_power_of_2(fri.last_layer_degree_bound)
            .ok_or(anyhow::anyhow!("Invalid last layer degree bound"))?;
        let fri = FriConfig {
            log_input_size: layer_log_sizes[0],
            n_layers: fri_step_list.len() as u32,
            inner_layers: fri_step_list[1..]
                .iter()
                .zip(layer_log_sizes[2..].iter())
                .map(|(layer_steps, layer_log_rows)| TableCommitmentConfig {
                    n_columns: 2_u32.pow(*layer_steps),
                    vector: VectorCommitmentConfig {
                        height: *layer_log_rows,
                        n_verifier_friendly_commitment_layers:
                            n_verifier_friendly_commitment_layers,
                    },
                })
                .collect(),
            fri_step_sizes: fri_step_list,
            log_last_layer_degree_bound,
        };

        Ok(StarkConfig {
            traces,
            composition,
            fri,
            proof_of_work,
            log_trace_domain_size: self.log_trace_domain_size()?,
            n_queries,
            log_n_cosets: stark.log_n_cosets,
            n_verifier_friendly_commitment_layers,
        })
    }
    fn log_trace_domain_size(&self) -> anyhow::Result<u32> {
        let consts = self.public_input.layout.get_consts();
        let effective_component_height = Self::COMPONENT_HEIGHT * consts.cpu_component_step;
        log2_if_power_of_2(effective_component_height * self.public_input.n_steps)
            .ok_or(anyhow::anyhow!("Invalid cpu component step"))
    }
    fn log_eval_damain_size(&self) -> anyhow::Result<u32> {
        Ok(self.log_trace_domain_size()? + self.proof_parameters.stark.log_n_cosets)
    }
    fn layer_log_sizes(&self) -> anyhow::Result<Vec<u32>> {
        let mut layer_log_sizes = vec![self.log_eval_damain_size()?];
        for layer_step in &self.proof_parameters.stark.fri.fri_step_list {
            layer_log_sizes.push(layer_log_sizes.last().unwrap() - layer_step);
        }
        Ok(layer_log_sizes)
    }
    fn stark_unsent_commitment(&self, annotations: &Annotations) -> StarkUnsentCommitment {
        StarkUnsentCommitment {
            traces: TracesUnsentCommitment {
                original: annotations.original_commitment_hash.clone(),
                interaction: annotations.interaction_commitment_hash.clone(),
            },
            composition: annotations.composition_commitment_hash.clone(),
            oods_values: annotations.oods_values.clone(),
            fri: FriUnsentCommitment {
                inner_layers: annotations.fri_layers_commitments.clone(),
                last_layer_coefficients: annotations.fri_last_layer_coefficients.clone(),
            },
            proof_of_work: ProofOfWorkUnsentCommitment {
                nonce: annotations.proof_of_work_nonce.clone(),
            },
        }
    }
    fn stark_witness(&self, annotations: &Annotations) -> StarkWitness {
        StarkWitness {
            traces_decommitment: TracesDecommitment {
                original: TableDecommitment {
                    n_values: annotations.original_witness_leaves.len(),
                    values: annotations.original_witness_leaves.clone(),
                },
                interaction: TableDecommitment {
                    n_values: annotations.interaction_witness_leaves.len(),
                    values: annotations.interaction_witness_leaves.clone(),
                },
            },
            traces_witness: TracesWitness {
                original: TableCommitmentWitness {
                    vector: VectorCommitmentWitness {
                        n_authentications: annotations.original_witness_authentications.len(),
                        authentications: annotations.original_witness_authentications.clone(),
                    },
                },
                interaction: TableCommitmentWitness {
                    vector: VectorCommitmentWitness {
                        n_authentications: annotations.interaction_witness_authentications.len(),
                        authentications: annotations.interaction_witness_authentications.clone(),
                    },
                },
            },
            composition_decommitment: TableDecommitment {
                n_values: annotations.composition_witness_leaves.len(),
                values: annotations.composition_witness_leaves.clone(),
            },
            composition_witness: TableCommitmentWitness {
                vector: VectorCommitmentWitness {
                    n_authentications: annotations.composition_witness_authentications.len(),
                    authentications: annotations.composition_witness_authentications.clone(),
                },
            },
            fri_witness: FriWitness {
                layers: annotations.fri_witnesses.iter().map(|w| FriLayerWitness {
                    n_leaves: w.leaves.len(),
                    leaves: w.leaves.clone(),
                    table_witness: TableCommitmentWitness {
                        vector: VectorCommitmentWitness {
                            n_authentications: w.authentications.len(),
                            authentications: w.authentications.clone(),
                        },
                    },
                }).collect(),
            },
        }
    }
}

impl TryFrom<ProofJSON> for StarkProof {
    type Error = anyhow::Error;
    fn try_from(value: ProofJSON) -> anyhow::Result<Self> {
        let config = value.stark_config()?;

        let annotations = Annotations::new(
            &value
                .annotations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            value.proof_parameters.stark.fri.fri_step_list.len(),
        )?;
        let unsent_commitment = value.stark_unsent_commitment(&annotations);
        let witness = value.stark_witness(&annotations);

        Ok(StarkProof {
            config,
            unsent_commitment,
            witness
        })
    }
}
