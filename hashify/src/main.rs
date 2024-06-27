#![deny(
    warnings,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

use clap::{App, Arg, ArgMatches, SubCommand};
use colored::*;
use serious::Encoding as Code;
use sha1::Sha1;
use sha2::Digest;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use stringreader::StringReader;

#[cfg(target_pointer_width = "64")]
use blake2::Blake2b as Blake2_512;
#[cfg(target_pointer_width = "32")]
use blake2::Blake2s as Blake2_512;
use digest::typenum::U64;
use digest::FixedOutputReset;

mod blake2t;
use blake2t::{Blake2_256, Blake2_384};

mod blake3t;
use blake3t::{Blake3_256, Blake3_384, Blake3_512};

mod constants;
use constants::*;

fn main() {
    let valid_hashes = [
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        SHA2_224,
        SHA2_256,
        SHA2_384,
        SHA2_512,
        SHA2_512_T224,
        SHA2_512_T256,
        BLAKE2_256,
        BLAKE2_384,
        BLAKE2_512,
        BLAKE3_256,
        BLAKE3_384,
        BLAKE3_512,
        WHIRLPOOL,
        SHA1,
        RIPEMD320,
        RIPEMD160,
        RIPEMD128,
        MD5,
    ];
    let encodings = serious::Encoding::values()
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<String>>();
    let encs = encodings.iter().map(|e| e.as_str()).collect::<Vec<&str>>();
    let default_enc = Code::LowHex.to_string();
    let create_default_type = ["sha3-256", "sha2-256", "sha2-512-t256", "blake2-256"].join(",");
    let matches = App::new("Hashify")
        .version("0.1")
        .author("Michael Lodder")
        .about("Hashify will produce checksums using many different hashes or check that a given input (file or text) matches a given checksum")
        .subcommand(SubCommand::with_name("verify")
            .about("Verify an input matches a digest. If no input is specified or input is '-', input is received from STDIN")
            .arg(Arg::with_name("type")
                 .short("t")
                 .long("type")
                 .value_name("VERIFY_HASH_TYPE")
                 .help("The specific hash to use to compute the checksum.")
                 .takes_value(true)
                 .possible_values(&valid_hashes)
                 .value_delimiter(",")
                 .allow_hyphen_values(true)
                 .required(false))
            .arg(Arg::with_name("encoding")
                .short("e")
                .long("encoding")
                .value_name("VERIFY_ENCODING")
                .help("The checksum encoding can only specify one.")
                .takes_value(true)
                .possible_values(encs.as_slice())
                .max_values(1)
                .required(false))
            .arg(Arg::with_name("byteorder")
                .short("b")
                .long("byteorder")
                .help("The checksum byte order.")
                .value_name("VERIFY_BYTE_ORDER")
                .takes_value(true)
                .possible_values(&["little", "big"])
                .max_values(1)
                .required(false))
            .arg(Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Show all tried algorithms in output.")
                .takes_value(false)
                .required(false))
            .arg(Arg::with_name("CHECKSUM")
                .help("The checksum file or text to compare.")
                .required(true)
                .index(1))
            .arg(Arg::with_name("INPUT")
                .help("The input file or text to check. If no input is specified or input is '-', input is received from STDIN")
                .required(false)
                .index(2)))
        .subcommand(SubCommand::with_name("create")
            .about("Compute the digest checksum for a given input. If no input is specified or input is '-', input is received from STDIN")
            .arg(Arg::with_name("type")
                 .short("t")
                 .long("type")
                 .value_name("OUT_HASH_TYPE")
                 .help("The specific hash to use to compute the checksum")
                 .takes_value(true)
                 .possible_values(&valid_hashes)
                 .value_delimiter(",")
                 .allow_hyphen_values(true)
                 .default_value(&create_default_type)
                 .required(false))
            .arg(Arg::with_name("encoding")
                .short("e")
                .long("encoding")
                .value_name("OUT_ENCODING")
                .help("The output encoding.")
                .takes_value(true)
                .possible_values(encs.as_slice())
                .value_delimiter(",")
                .default_value(&default_enc)
                .required(false))
            .arg(Arg::with_name("byteorder")
                .short("b")
                .long("byteorder")
                .help("The output byte ordering.")
                .value_name("OUT_BYTE_ORDER")
                .takes_value(true)
                .possible_values(&["little", "big"])
                .value_delimiter(",")
                .default_value("big")
                .required(false))
            .arg(Arg::with_name("INPUT")
                 .help("The file or text to process. If no input is specified or input is '-', input is received from STDIN")
                 .required(false)
                 .index(1))
         ).get_matches();

    if let Some(matches) = matches.subcommand_matches("create") {
        create(matches);
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        verify(matches);
    } else {
        quit("Please specify a command to run [create | verify]".to_string());
    }
}

fn create(matches: &ArgMatches) {
    let hash_types: Vec<&str> = matches.values_of("type").unwrap().collect();
    let out_hash = get_hashes_from_input(matches, hash_types);
    let label_width = out_hash
        .iter()
        .fold(0usize, |a, (label, _)| std::cmp::max(a, label.len()));
    let byte_width = matches
        .values_of("byteorder")
        .unwrap()
        .fold(0usize, |a, s| std::cmp::max(a, s.len()));
    let enc_width = matches
        .values_of("encoding")
        .unwrap()
        .fold(0usize, |a, s| std::cmp::max(a, s.len()));

    for (label, hash) in out_hash {
        let l = name_color(&label);
        for bo in matches.values_of("byteorder").unwrap() {
            let bytes: Vec<u8> = match bo {
                "big" => hash.to_vec(),
                "little" => {
                    let mut temp = hash.to_vec();
                    temp.reverse();
                    temp
                }
                _ => {
                    quit(format!("Unrecognized byteorder - \"{}\"", bo));
                    Vec::new()
                }
            };

            let encodings = matches
                .values_of("encoding")
                .unwrap()
                .map(|e| Code::parse(e).unwrap())
                .collect::<Vec<Code>>();
            for enc in encodings {
                match enc {
                    Code::Blob => {
                        print!(
                            "{l:label_width$} {bo:byte_width$}-endian {enc:enc_width$} - blob",
                            l = l,
                            bo = bo,
                            enc = "",
                            label_width = label_width,
                            byte_width = byte_width,
                            enc_width = enc_width
                        );
                        io::stdout().write_all(bytes.as_slice()).unwrap();
                        io::stdout().flush().unwrap();
                    }
                    e => {
                        println!(
                            "{:label_width$} {:byte_width$}-endian {:enc_width$} - {}",
                            l,
                            bo,
                            e.to_string(),
                            Code::encode(bytes.as_slice(), e).into_string(),
                            label_width = label_width,
                            byte_width = byte_width,
                            enc_width = enc_width
                        );
                    }
                }
            }
        }
    }
}

fn verify(matches: &ArgMatches) {
    let mut checksum = Vec::new();
    let checksum_text = matches.value_of("CHECKSUM").unwrap();
    match get_file(checksum_text) {
        Some(file) => {
            let mut f = File::open(file.as_path())
                .unwrap_or_else(|_| panic!("Unable to read file {}", file.to_str().unwrap()));
            match f.read_to_end(&mut checksum) {
                Ok(_) => (),
                Err(e) => quit(format!(
                    "An error occurred while reading checksum file - \"{}\"",
                    e
                )),
            };
        }
        None => checksum = checksum_text.as_bytes().to_vec(),
    };

    let mut checksum_str = String::new();
    if let Ok(s) = String::from_utf8(checksum.to_vec()).map_err(|e| format!("{}", e)) {
        checksum_str = s.to_string();
    } else {
        quit("Checksum cannot be read properly".to_string());
    }

    let encoding_checksums = get_encoding_checksums(matches, &checksum_str, &checksum);

    let mut hash_types = Vec::new();

    if let Some(ht) = matches.values_of("type") {
        hash_types = ht.collect();
    } else {
        for cksum in encoding_checksums.values() {
            match cksum.len() {
                16 => {
                    hash_types.push(RIPEMD128);
                    hash_types.push(MD5);
                }
                20 => {
                    hash_types.push(SHA1);
                    hash_types.push(RIPEMD160);
                }
                28 => {
                    hash_types.push(SHA2_224);
                    hash_types.push(SHA2_512_T224);
                    hash_types.push(SHA3_224);
                }
                32 => {
                    hash_types.push(SHA2_256);
                    hash_types.push(SHA2_512_T256);
                    hash_types.push(BLAKE2_256);
                    hash_types.push(SHA3_256);
                    hash_types.push(BLAKE3_256);
                }
                40 => {
                    hash_types.push(RIPEMD320);
                }
                48 => {
                    hash_types.push(SHA2_384);
                    hash_types.push(SHA3_384);
                    hash_types.push(BLAKE2_384);
                    hash_types.push(BLAKE3_384);
                }
                64 => {
                    hash_types.push(SHA2_512);
                    hash_types.push(SHA3_512);
                    hash_types.push(BLAKE2_512);
                    hash_types.push(BLAKE3_512);
                    hash_types.push(WHIRLPOOL);
                }
                _ => (),
            }
        }
    }

    if hash_types.is_empty() {
        quit("Unknown checksum length".to_string());
    }

    let mut big_endian = true;
    let mut little_endian = true;
    if let Some(bo) = matches.value_of("byteorder") {
        big_endian = bo == "big";
        little_endian = bo == "little";
    }

    let hashes = get_hashes_from_input(matches, hash_types);

    let mut trials = Vec::new();
    let mut name_width = 0;
    let mut enc_width = 0;
    let mut byte_width = 0;
    for (name, output) in &hashes {
        for (encoding, cksum) in &encoding_checksums {
            if big_endian {
                let l = name_color(name);
                if output == cksum {
                    name_width = std::cmp::max(name_width, name.len());
                    enc_width = std::cmp::max(enc_width, encoding.len());
                    byte_width = std::cmp::max(byte_width, 10);
                    trials.insert(0, (l, "big-endian", encoding, "pass".green()));
                } else {
                    name_width = std::cmp::max(name_width, name.len());
                    enc_width = std::cmp::max(enc_width, encoding.len());
                    byte_width = std::cmp::max(byte_width, 10);
                    trials.push((l, "big-endian", encoding, "fail".red()));
                }
            }
            if little_endian {
                let l = name_color(name);
                let mut temp = output.to_vec();
                temp.reverse();
                if temp == *cksum {
                    name_width = std::cmp::max(name_width, name.len());
                    enc_width = std::cmp::max(enc_width, encoding.len());
                    byte_width = std::cmp::max(byte_width, 13);
                    trials.insert(0, (l, "little-endian", encoding, "pass".green()));
                } else {
                    name_width = std::cmp::max(name_width, name.len());
                    enc_width = std::cmp::max(enc_width, encoding.len());
                    byte_width = std::cmp::max(byte_width, 13);
                    trials.push((l, "little-endian", encoding, "fail".red()));
                }
            }
        }
    }

    match matches.occurrences_of("verbose") {
        1 => {
            for trial in trials {
                println!(
                    "{:name_width$} {:byte_width$} {:enc_width$} - {}",
                    trial.0,
                    trial.1,
                    trial.2,
                    trial.3,
                    name_width = name_width,
                    byte_width = byte_width,
                    enc_width = enc_width
                );
            }
        }
        _ => println!(
            "{:name_width$} {:byte_width$} {:enc_width$} - {}",
            trials[0].0,
            trials[0].1,
            trials[0].2,
            trials[0].3,
            name_width = trials[0].0.len(),
            byte_width = trials[0].1.len(),
            enc_width = trials[0].2.len()
        ),
    };
}

fn name_color(s: &str) -> ColoredString {
    match s {
        MD5 => s.red(),
        SHA1 | RIPEMD320 | RIPEMD160 | RIPEMD128 => s.yellow(),
        _ => s.normal(),
    }
}

fn get_hashes_from_input(matches: &ArgMatches, hash_types: Vec<&str>) -> Vec<(String, Vec<u8>)> {
    match matches.value_of("INPUT") {
        Some(text) => {
            if text == "-" {
                let mut f = io::stdin();
                hash_stream(&mut f, hash_types)
            } else {
                match get_file(text) {
                    Some(file) => {
                        let mut res = Vec::new();
                        match File::open(file.as_path()) {
                            Ok(mut f) => res = hash_stream(&mut f, hash_types),
                            Err(_) => {
                                quit(format!("Unable to read file {}", file.to_str().unwrap()))
                            }
                        };
                        res
                    }
                    None => {
                        let mut f = StringReader::new(text);
                        hash_stream(&mut f, hash_types)
                    }
                }
            }
        }
        None => {
            let mut f = io::stdin();
            hash_stream(&mut f, hash_types)
        }
    }
}

fn get_encoding_checksums(
    matches: &ArgMatches,
    checksum_str: &str,
    checksum: &[u8],
) -> HashMap<String, Vec<u8>> {
    let mut encoding_checksums = HashMap::new();
    if let Some(encoding) = matches.value_of("encoding") {
        let enc = Code::parse(encoding).unwrap();
        match enc {
            Code::Blob => {
                encoding_checksums.insert(encoding.to_string(), checksum.to_vec());
            }
            e => match Code::decode(checksum_str, e) {
                Ok(c) => {
                    encoding_checksums.insert(encoding.to_string(), c);
                }
                Err(err) => {
                    quit(err);
                }
            },
        }
    } else {
        //Try to figure out the encoding
        for v in Code::values() {
            if let Ok(bytes) = Code::decode(checksum_str, v) {
                encoding_checksums.insert(v.to_string(), bytes);
            }
        }
        if encoding_checksums.is_empty() {
            encoding_checksums.insert("blob".to_string(), checksum.to_vec());
        }
    }
    encoding_checksums
}

fn hash_stream<R: Read>(f: &mut R, hash_types: Vec<&str>) -> Vec<(String, Vec<u8>)> {
    let mut out_hash = Vec::new();

    let mut buffer = [0u8; 65536];

    let mut halg: Vec<Box<dyn FixedDigest>> = Vec::with_capacity(hash_types.len());
    for hash in &hash_types {
        match *hash {
            SHA3_224 => halg.push(Box::new(sha3::Sha3_224::new())),
            SHA3_256 => halg.push(Box::new(sha3::Sha3_256::new())),
            SHA3_384 => halg.push(Box::new(sha3::Sha3_384::new())),
            SHA3_512 => halg.push(Box::new(sha3::Sha3_512::new())),
            SHA2_224 => halg.push(Box::new(sha2::Sha224::new())),
            SHA2_256 => halg.push(Box::new(sha2::Sha256::new())),
            SHA2_512_T224 => halg.push(Box::new(sha2::Sha512_224::new())),
            SHA2_512_T256 => halg.push(Box::new(sha2::Sha512_256::new())),
            SHA2_384 => halg.push(Box::new(sha2::Sha384::new())),
            SHA2_512 => halg.push(Box::new(sha2::Sha512::new())),
            SHA1 => halg.push(Box::new(Sha1::new())),
            BLAKE2_256 => halg.push(Box::new(Blake2_256::new())),
            BLAKE2_384 => halg.push(Box::new(Blake2_384::new())),
            BLAKE2_512 => halg.push(Box::new(Blake2_512::new())),
            BLAKE3_256 => halg.push(Box::new(Blake3_256::new())),
            BLAKE3_384 => halg.push(Box::new(Blake3_384::new())),
            BLAKE3_512 => halg.push(Box::new(Blake3_512::new())),
            WHIRLPOOL => halg.push(Box::new(whirlpool::Whirlpool::new())),
            RIPEMD320 => halg.push(Box::new(ripemd::Ripemd320::new())),
            RIPEMD160 => halg.push(Box::new(ripemd::Ripemd160::new())),
            RIPEMD128 => halg.push(Box::new(ripemd::Ripemd128::new())),
            MD5 => halg.push(Box::new(md5::Md5::new())),
            e => quit(format!("Unrecognized checksum \"{}]\"", e)),
        }
    }

    let mut read = f.read(&mut buffer);
    while read.is_ok() {
        let n = read.unwrap();

        if n == 0 {
            break;
        }

        for hash in halg.iter_mut() {
            hash.update(&buffer[..n]);
        }

        read = f.read(&mut buffer);
    }

    for (hash, hash_type) in halg.iter_mut().zip(hash_types.iter()) {
        let digest = hash.finalize_reset();
        out_hash.push((hash_type.to_string(), digest))
    }
    out_hash
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

trait FixedDigest {
    fn update(&mut self, data: &[u8]);
    fn finalize_reset(&mut self) -> Vec<u8>;
}

macro_rules! impl_fixed_digest {
    ($($name:ident),+) => {
        $(
        impl FixedDigest for $name {
            fn update(&mut self, data: &[u8]) {
                <Self as digest::Update>::update(self, data);
            }

            fn finalize_reset(&mut self) -> Vec<u8> {
                <Self as FixedOutputReset>::finalize_fixed_reset(self).to_vec()
            }
        }
        )+
    };
    ($($name:path),+) => {
        $(
        impl FixedDigest for $name {
            fn update(&mut self, data: &[u8]) {
                <Self as digest::Update>::update(self, data);
            }

            fn finalize_reset(&mut self) -> Vec<u8> {
                <Self as FixedOutputReset>::finalize_fixed_reset(self).to_vec()
            }
        }
        )+
    };
}

impl_fixed_digest!(
    sha2::Sha224,
    sha2::Sha256,
    sha2::Sha384,
    sha2::Sha512,
    sha3::Sha3_224,
    sha3::Sha3_256,
    sha3::Sha3_384,
    sha3::Sha3_512,
    sha2::Sha512_224,
    sha2::Sha512_256,
    whirlpool::Whirlpool,
    ripemd::Ripemd128,
    ripemd::Ripemd160,
    ripemd::Ripemd320,
    md5::Md5
);
impl_fixed_digest!(
    Blake2_256,
    Blake2_384,
    Blake2_512<U64>,
    Blake3_256,
    Blake3_384,
    Blake3_512,
    Sha1
);
