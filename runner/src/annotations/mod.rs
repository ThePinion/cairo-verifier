use self::annotation_kind::{Annotation, ZAlpha};

pub mod annotation_kind;
pub mod extract;


pub struct Annotations {
    pub z: u32,
    pub alpha: u32,
    pub original_commitment_hash: u32,
    pub interaction_commitment_hash: u32,
    pub composition_commitment_hash: u32,
    pub oods_values: Vec<u32>,
    pub fri_layers_commitments: Vec<u32>,
    pub fri_last_layer_coefficients: Vec<u32>,
    pub proof_of_work_nonce: Vec<u32>,
    pub original_witness_leaves: Vec<u32>,
    pub original_witness_authentications: Vec<u32>,
    pub interaction_witness_leaves: Vec<u32>,
    pub interaction_witness_authentications: Vec<u32>,
    pub composition_witness_leaves: Vec<u32>,
    pub composition_witness_authentications: Vec<u32>,
    pub fri_witnesses: Vec<FriWitness>,
}

impl Annotations {
    #[rustfmt::skip]
    pub fn new(annotations: &[&str], n_fri_layers: usize) -> anyhow::Result<Annotations> {
        let ZAlpha {z, alpha} = ZAlpha::extract(annotations)?;
        Ok(Annotations {
            z,
            alpha,
            original_commitment_hash: 
                *Annotation::OriginalCommitmentHash.extract(annotations)
                    .get(0).ok_or(anyhow::anyhow!("No OriginalCommitmentHash in annotations!"))?,
            interaction_commitment_hash: 
                *Annotation::InteractionCommitmentHash.extract(annotations)
                    .get(0).ok_or(anyhow::anyhow!("No InteractionCommitmentHash in annotations!"))?,
            composition_commitment_hash: 
                *Annotation::CompositionCommitmentHash.extract(annotations)
                    .get(0).ok_or(anyhow::anyhow!("No CompositionCommitmentHash in annotations!"))?,
            oods_values: 
                Annotation::OodsValues.extract(annotations),
            fri_layers_commitments: 
                Annotation::FriLayersCommitments.extract(annotations),
            fri_last_layer_coefficients: 
                Annotation::FriLastLayerCoefficients.extract(annotations),
            proof_of_work_nonce: 
                Annotation::ProofOfWorkNonce.extract(annotations),
            original_witness_leaves: 
                Annotation::OriginalWitnessLeaves.extract(annotations),
            original_witness_authentications: 
                Annotation::OriginalWitnessAuthentications.extract(annotations),
            interaction_witness_leaves: 
                Annotation::InteractionWitnessLeaves.extract(annotations),
            interaction_witness_authentications: 
                Annotation::InteractionWitnessAuthentications.extract(annotations),
            composition_witness_leaves: 
                Annotation::CompositionWitnessLeaves.extract(annotations),
            composition_witness_authentications: 
                Annotation::CompositionWitnessAuthentications.extract(annotations),
            fri_witnesses: (1..n_fri_layers).map(|i| FriWitness {
                layer: i,
                leaves: 
                    Annotation::FriWitnessesLeaves(i).extract(annotations),
                authentications: 
                    Annotation::FriWitnessesAuthentications(i).extract(annotations)
            }).collect()
        })
    }
}

pub struct FriWitness {
    layer: usize,
    leaves: Vec<u32>,
    authentications: Vec<u32>,
}
