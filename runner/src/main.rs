use std::io::{stdin, Read};

use clap::Parser;

use crate::{ast::Exprs, json_parser::ProofJSON, stark_proof::StarkProof};

mod annotations;
mod ast;
mod json_parser;
mod layout;
mod stark_proof;
mod utils;
mod builtins;

// lalrpop_mod!(pub parser);

fn main() -> anyhow::Result<()> {
    let mut input = String::new();
    stdin().read_to_string(&mut input)?;
    let proof_json = serde_json::from_str::<ProofJSON>(&input)?;
    let stark_proof = StarkProof::try_from(proof_json)?;
    let exprs = Exprs::from(stark_proof);
    let result = exprs.to_string();

    println!("{result:?}");
    Ok(())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to compiled sierra file
    target: String,
}

// #[allow(dead_code)]
// fn old_main() -> anyhow::Result<()> {
//     let cli = Cli::parse();
//     let mut input = String::new();
//     stdin().read_to_string(&mut input)?;

//     let parsed = parser::CairoParserOutputParser::new()
//         .parse(&input)
//         .map_err(|e| anyhow::anyhow!("{}", e))?;
//     let result = parsed.to_string();

//     let target = cli.target;
//     let function = "main";
//     let args: VecFelt252 = serde_json::from_str(&result).unwrap();

//     let result = run(&target, function, &[Arg::Array(args.to_vec())])?;

//     println!("{result:?}");
//     Ok(())
// }
