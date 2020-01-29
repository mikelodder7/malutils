#![deny(
    warnings,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

use clap::{App, Arg};
use serious::Encoding::{self as Code, *};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use stringreader::StringReader;

fn main() {
    let inencodings = vec![
        Blob.to_string(), Binary.to_string(), Base10.to_string(),
        Base58.to_string(), Base62.to_string(), Base64.to_string(),
        Base64Url.to_string(), BitCoin.to_string(), Flickr.to_string(),
        LowHex.to_string(), Monero.to_string(), Ripple.to_string()
    ];
    let inencs = inencodings.iter().map(|e| e.as_str()).collect::<Vec<&str>>();

    let outencs = vec![
        "blob", "binary", "base10",
        "base58", "base62", "base64",
        "base64url", "bitcoin", "flickr",
        "lowhex", "uphex", "monero", "ripple"
    ];

    let matches = App::new("Serious")
    .version("0.1")
    .author("Michael Lodder")
    .about("Serious will serialize data into many different formats. The result is converted from the designated input encoding to the designated output encoding.")
        .arg(Arg::with_name("input")
             .short("i")
             .long("input")
             .value_name("INPUT_ENCODING")
             .help("The input encoding to parse.")
             .takes_value(true)
             .possible_values(inencs.as_slice())
             .max_values(1)
             .allow_hyphen_values(true)
             .required(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("OUTPUT_ENCODING")
            .help("The output encoding.")
            .takes_value(true)
            .possible_values(outencs.as_slice())
            .max_values(1)
            .required(true))
        .arg(Arg::with_name("TEXT")
            .help("The input file or text to change serialization. If no input is specified or input is '-', input is received from STDIN")
            .required(true)
            .index(1))
     .get_matches();

    let input_encoding = Code::parse(matches.value_of("input").unwrap()).unwrap();
    let output_encoding = Code::parse(matches.value_of("output").unwrap()).unwrap();
    match matches.value_of("TEXT") {
        Some(text) => {
            if text == "-" {
                let mut f = io::stdin();
                recode_stream(&mut f, input_encoding, output_encoding);
            } else {
                match get_file(text) {
                    Some(file) => {
                        match File::open(file.as_path()) {
                            Ok(mut f) => recode_stream(&mut f, input_encoding, output_encoding),
                            Err(_) => {
                                quit(format!("Unable to read file {}", file.to_str().unwrap()));
                            }
                        };
                    }
                    None => {
                        let mut f = StringReader::new(text);
                        recode_stream(&mut f, input_encoding, output_encoding);
                    }
                }
            }
        }
        None => {
            let mut f = io::stdin();
            recode_stream(&mut f, input_encoding, output_encoding);
        }
    };
}

fn recode_stream<R: Read>(f: &mut R, ie: Code, oe: Code) {
    let mut out_hash = Vec::new();

    let mut buffer = [0u8; 65536];

    let mut read = f.read(&mut buffer);
    while read.is_ok() {
        let n = read.unwrap();

        if n == 0 {
            break;
        }

        out_hash.write(&buffer[..n]).unwrap();
        read = f.read(&mut buffer);
    }

    let res = String::from_utf8(out_hash).unwrap();
    println!("{}", Code::recode(res, ie, oe).unwrap());
}

fn get_file(name: &str) -> Option<PathBuf> {
    let mut file = PathBuf::new();
    file.push(name);
    if file.as_path().is_file() {
        let metadata = file
            .as_path()
            .symlink_metadata()
            .expect("symlink_metadata call failed");
        if metadata.file_type().is_symlink() {
            match file.as_path().read_link() {
                Ok(f) => file = f,
                Err(_) => {
                    quit(format!("Can't read the symbolic link: {}", name));
                }
            };
        }
        Some(file)
    } else {
        None
    }
}

fn quit(final_message: String) {
    println!("{}", final_message);
    std::process::exit(1);
}
