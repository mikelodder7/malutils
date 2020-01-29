use clap::{App, Arg};
use sha2::digest::Digest;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use serious::Encoding as Code;

pub enum CommandLineArgs {
    Bytes(usize),
    Encoding(Code),
    Seed(Vec<u8>),
}

pub fn parse_cmd_line() -> Result<BTreeMap<&'static str, CommandLineArgs>, String> {
    let encodings = vec![
        Code::Blob.to_string(), Code::Binary.to_string(), Code::Base10.to_string(),
        Code::Base58.to_string(), Code::Base62.to_string(), Code::Base64.to_string(),
        Code::Base64Url.to_string(), Code::BitCoin.to_string(), Code::Flickr.to_string(),
        Code::LowHex.to_string(), Code::Monero.to_string(), Code::Ripple.to_string()
    ];
    let enc_ref = encodings.iter().map(|e| e.as_str()).collect::<Vec<&str>>();
    let matches = App::new("randr")
        .version("0.1")
        .author("Michael Lodder")
        .about("randr is a tool for generating random data and encoding it in any format")
        .arg(
            Arg::with_name("bytes")
                .help("The number of bytes to randomly generate")
                .short("b")
                .long("bytes")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("encoding")
                .help("The output encoding to use.")
                .short("e")
                .long("encoding")
                .required(false)
                .takes_value(true)
                .possible_values(enc_ref.as_slice())
                .value_delimiter(",")
                .default_value("hex"),
        )
        .arg(
            Arg::with_name("seed")
                .help("A starting value to generate random data")
                .short("s")
                .long("seed")
                .required(false)
                .takes_value(false),
        )
        .get_matches();

    let mut args = BTreeMap::new();

    let bytes = matches.value_of("bytes").unwrap();
    match bytes.parse::<usize>() {
        Ok(n) => {
            if n == 0 {
                return Err("Expected argument 'bytes=#' and # must be greater than 0".to_string());
            }
            args.insert("bytes", CommandLineArgs::Bytes(n));
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }

    let encoding = matches.value_of("encoding").unwrap_or("hex");
    args.insert("encoding", CommandLineArgs::Encoding(Code::parse(encoding).unwrap()));

    if matches.is_present("seed") {
        let temp;
        match matches.value_of("seed") {
            Some(s) => match get_file(s)? {
                Some(file) => match File::open(file.as_path()) {
                    Ok(mut f) => {
                        temp = read_stream(&mut f);
                    }
                    Err(_) => {
                        return Err(format!("Unable to read file {}", file.to_str().unwrap()));
                    }
                },
                None => {
                    temp = s.as_bytes().to_vec();
                }
            },
            None => {
                if atty::is(atty::Stream::Stdin) {
                    temp = rpassword::read_password_from_tty(Some("Enter Seed: "))
                        .unwrap()
                        .as_bytes()
                        .to_vec();
                } else {
                    let mut f = io::stdin();
                    temp = read_stream(&mut f);
                }
            }
        }
        args.insert(
            "seed",
            CommandLineArgs::Seed(sha2::Sha256::digest(temp.as_slice()).to_vec()),
        );
    }

    Ok(args)
}

fn get_file(name: &str) -> Result<Option<PathBuf>, String> {
    let mut file = PathBuf::new();
    file.push(name);
    if file.as_path().is_file() {
        let metadata = file
            .as_path()
            .symlink_metadata()
            .map_err(|_| "symlink_metadata call failed".to_string())?;
        if metadata.file_type().is_symlink() {
            match file.as_path().read_link() {
                Ok(f) => file = f,
                Err(_) => return Err(format!("Can't read the symbolic link: {}", name)),
            };
        }
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

fn read_stream<R: Read>(f: &mut R) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];

    let mut read = f.read(&mut buffer);
    while read.is_ok() {
        let n = read.unwrap();

        if n == 0 {
            break;
        }

        bytes.extend_from_slice(&buffer[..n]);

        read = f.read(&mut buffer);
    }

    bytes
}
