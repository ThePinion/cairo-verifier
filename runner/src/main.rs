use std::io::{stdin, Read};

use cairo_args_runner::{Arg, Felt252, VecFelt252};
use clap::Parser;

use crate::{ast::Exprs, json_parser::ProofJSON, stark_proof::StarkProof};

mod annotations;
mod ast;
mod json_parser;
mod layout;
mod stark_proof;
mod utils;
mod builtins;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
enum Cli {
    Parse,
    Verify {
        /// Path to compiled sierra file
        target: String,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse() {
        Cli::Parse => println!("{}", parse()?),
        Cli::Verify { target } => println!("{:?}", run(parse()?, target)?)
    }
    Ok(())
}

fn parse() -> anyhow::Result<String> {
    let mut input = String::new();
    stdin().read_to_string(&mut input)?;
    let proof_json = serde_json::from_str::<ProofJSON>(&input)?;
    let stark_proof = StarkProof::try_from(proof_json)?;
    let exprs = Exprs::from(stark_proof);
    Ok(exprs.to_string())
}

fn run(parsed: String, target: String) -> anyhow::Result<Vec<Felt252>> {
        let target = target;
        let function = "main";
        let args: VecFelt252 = serde_json::from_str(&parsed).unwrap();
        Ok(cairo_args_runner::run(&target, function, &[Arg::Array(args.to_vec())])?)
}
