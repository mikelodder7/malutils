#![deny(
    warnings,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

mod options;

use crate::options::CommandLineArgs;
use rand::prelude::*;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use serious::Encoding as Code;
use std::io::{self, Write};

fn main() {
    let args;
    match options::parse_cmd_line() {
        Ok(v) => args = v,
        Err(e) => {
            io::stdout().write_all(e.as_bytes()).unwrap();
            io::stdout().flush().unwrap();
            std::process::exit(1);
        }
    };

    let mut data = vec![0u8; 0];
    if let CommandLineArgs::Bytes(u) = &args["bytes"] {
        data = vec![0u8; *u];
    }

    let mut seed = None;
    if args.contains_key("seed") {
        if let CommandLineArgs::Seed(u) = &args["seed"] {
            seed = Some(u);
        }
    }

    let mut rng: Box<dyn RngCore> = if let Some(s) = seed {
        Box::new(ChaChaRng::from_seed(*arrayref::array_ref!(
            s.as_slice(),
            0,
            32
        )))
    } else {
        Box::new(OsRng {})
    };
    rng.fill_bytes(data.as_mut_slice());

    let mut encoding = Code::LowHex;
    if let CommandLineArgs::Encoding(e) = &args["encoding"] {
        encoding = *e;
    }

    match encoding {
        Code::Blob => io::stdout().write_all(data.as_slice()).unwrap(),
        e => println!("{}", Code::encode(data, e).into_string()),
    };
}
