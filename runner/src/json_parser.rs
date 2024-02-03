use serde::Deserialize;

use crate::{
    layout::Layout,
    stark_proof::{
        FriConfig, ProofOfWorkConfig, StarkConfig, StarkProof, TableCommitmentConfig, TracesConfig,
        VectorCommitmentConfig,
    },
    utils::log2_if_power_of_2,
};

#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ProofJSON {
    proof_parameters: ProofParameters,
    annotations: Vec<Annotation>,
    public_input: PublicInput,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct Annotation {
    pub val: String,
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

impl<'de> Deserialize<'de> for Annotation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|val| Annotation { val })
    }
}

impl ProofJSON {
    const COMPONENT_HEIGHT: u32 = 16;
    pub fn to_stark_config(&self) -> anyhow::Result<StarkConfig> {
        let stark = &self.proof_parameters.stark;
        let n_verifier_friendly_commitment_layers = self.proof_parameters.n_verifier_friendly_commitment_layers;
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
                    n_columns: 2 * *layer_steps,
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
        dbg!(log2_if_power_of_2(effective_component_height * self.public_input.n_steps)
            .ok_or(anyhow::anyhow!("Invalid cpu component step")))
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
}

impl TryFrom<ProofJSON> for StarkProof {
    fn try_from(value: ProofJSON) -> anyhow::Result<Self> {
        let config = value.to_stark_config()?;
        Ok(StarkProof { config })
    }

    type Error = anyhow::Error;
}
