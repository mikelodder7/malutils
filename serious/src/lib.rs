#![deny(
    warnings,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

#[macro_export]
macro_rules! recode {
    ($in_data:expr, $src:expr, $tgt:expr) => {
        Encoding::recode($in_data, $src.into(), $tgt.into()).unwrap()
    };
}

#[macro_export]
macro_rules! encode {
    ($in_data:expr, $tgt:expr) => {
        Encoding::encode($in_data, $tgt.into()).into_string()
    };
}

#[macro_export]
macro_rules! decode {
    ($in_data:expr, $src:expr) => {
        Encoding::decode($in_data, $src.into()).unwrap()
    };
}

const BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

use num_bigint::BigUint;
use num_traits::Num;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct Encoder<I: AsRef<[u8]>> {
    input: I,
    encoding: Encoding
}

impl<I: AsRef<[u8]>> Encoder<I> {
    pub fn new(input: I, encoding: Encoding) -> Self {
        Encoder { input, encoding }
    }

    pub fn into_string(self) -> String {
        let s = self.input.as_ref();
        match self.encoding {
            Blob => String::from_utf8_lossy(s).to_string(),
            Binary => BigUint::from_bytes_be(s).to_str_radix(2),
            Base10 => BigUint::from_bytes_be(s).to_str_radix(10),
            Base58 | BitCoin => bs58::encode(s).into_string(),
            Base62 => base_x::encode(BASE62, s),
            Base64 => base64_url::base64::encode(s),
            Base64Url => base64_url::encode(s),
            Flickr => bs58::encode(s)
                .with_alphabet(bs58::alphabet::FLICKR)
                .into_string(),
            LowHex => hex::encode(s),
            Monero => bs58::encode(s)
                .with_alphabet(bs58::alphabet::MONERO)
                .into_string(),
            Ripple => bs58::encode(s)
                .with_alphabet(bs58::alphabet::RIPPLE)
                .into_string(),
            UpHex => hex::encode_upper(s),
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        match self.encoding {
            Blob => self.input.as_ref().to_vec(),
            _ => self.into_string().into_bytes()
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Encoding {
    Blob,
    Binary,
    Base10,
    Base58,
    Base62,
    Base64,
    Base64Url,
    BitCoin,
    Flickr,
    LowHex,
    Monero,
    Ripple,
    UpHex,
}

use Encoding::*;

impl Encoding {
    pub fn parse<I: AsRef<str>>(s: I) -> Result<Self, String> {
        let s = s.as_ref();
        match s {
            "blob" => Ok(Blob),
            "bin" | "binary" =>  Ok(Binary),
            "bs10" | "base10" => Ok(Base10),
            "bs58" | "base58" => Ok(Base58),
            "btc" | "bitcoin" => Ok(BitCoin),
            "bs62" | "base62" => Ok(Base62),
            "bs64" | "base64" => Ok(Base64),
            "bs64u" | "base64url" => Ok(Base64Url),
            "fkr" | "flickr" => Ok(Flickr),
            "lowhex" | "hex" => Ok(LowHex),
            "xmr" | "monero" => Ok(Monero),
            "xrp" | "ripple" => Ok(Ripple),
            "uhx" | "uphex" =>  Ok(UpHex),
            _ => Err(format!("Unknown encoding: {}", s))
        }
    }

    pub fn decode<T: AsRef<str>>(s: T, src: Self) -> Result<Vec<u8>, String> {
        let s = s.as_ref();
        match src {
            Blob => Ok(s.as_bytes().to_vec()),
            Binary => match BigUint::from_str_radix(s, 2) {
                Ok(n) => Ok(n.to_bytes_be()),
                Err(_) => Err(format!("Unable to convert from {}", src)),
            },
            Base10 => match BigUint::from_str_radix(s, 10) {
                Ok(n) => Ok(n.to_bytes_be()),
                Err(_) => Err(format!("Unable to convert from {}", src)),
            },
            Base58 | BitCoin => bs58::decode(s).into_vec().map_err(|e| e.to_string()),
            Base62 => base_x::decode(BASE62, s).map_err(|e| e.to_string()),
            Base64 => base64_url::base64::decode(s).map_err(|e| e.to_string()),
            Base64Url => base64_url::decode(s).map_err(|e| e.to_string()),
            Flickr => bs58::decode(s)
                .with_alphabet(bs58::alphabet::FLICKR)
                .into_vec()
                .map_err(|e| e.to_string()),
            LowHex | UpHex => hex::decode(s).map_err(|e| e.to_string()),
            Monero => bs58::decode(s)
                .with_alphabet(bs58::alphabet::MONERO)
                .into_vec()
                .map_err(|e| e.to_string()),
            Ripple => bs58::decode(s)
                .with_alphabet(bs58::alphabet::RIPPLE)
                .into_vec()
                .map_err(|e| e.to_string()),
        }
    }

    pub fn encode<T: AsRef<[u8]>>(s: T, tgt: Self) -> Encoder<T> {
        Encoder { input: s, encoding: tgt }
    }

    pub fn recode<T: AsRef<str>>(s: T, src: Self, tgt: Self) -> Result<String, String> {
        if src == Blob && tgt == Blob {
            Ok(s.as_ref().to_string())
        } else {
            let s = Encoding::decode(s, src)?;
            Ok(Encoding::encode(s.as_slice(), tgt).into_string())
        }
    }

    pub fn values() -> Vec<Self> {
        vec![
            Blob, Binary, Base10, Base58, Base62, Base64, Base64Url, BitCoin, Flickr, LowHex, Monero,
            Ripple, UpHex,
        ]
    }
}

impl Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Blob => write!(f, "blob"),
            Binary => write!(f, "binary"),
            Base10 => write!(f, "base10"),
            Base58 => write!(f, "base58"),
            BitCoin => write!(f, "bitcoin"),
            Base62 => write!(f, "base62"),
            Base64 => write!(f, "base64"),
            Base64Url => write!(f, "base64url"),
            Flickr => write!(f, "flickr"),
            LowHex => write!(f, "hex"),
            Monero => write!(f, "monero"),
            Ripple => write!(f, "ripple"),
            UpHex => write!(f, "uphex"),
        }
    }
}

impl From<&str> for Encoding {
    fn from(s: &str) -> Self {
        Encoding::parse(s).unwrap()
    }
}

impl From<String> for Encoding {
    fn from(s: String) -> Self {
        Encoding::parse(s.as_str()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn encode_decode() {
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; 64];
        rng.fill_bytes(buffer.as_mut_slice());

        let res = Encoding::encode(&buffer, Blob).into_vec();
        assert_eq!(buffer, res);

        for v in Encoding::values()[1..].iter() {
            let res = Encoding::encode(&buffer, *v).into_string();
            assert_eq!(buffer, Encoding::decode(res, *v).unwrap());
        }
    }

    #[test]
    fn macros() {
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; 64];
        rng.fill_bytes(buffer.as_mut_slice());

        for v in Encoding::values()[1..].iter() {
            let res = encode!(&buffer, v.to_string());
            assert_eq!(buffer, decode!(res, v.to_string()));
            let res = encode!(&buffer, *v);
            assert_eq!(buffer, decode!(res, *v));
        }
    }

    #[test]
    fn recode() {
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; 64];
        rng.fill_bytes(buffer.as_mut_slice());
        let encodings = Encoding::values();

        for i in 1..(encodings.len() - 1) {
            for j in 2..(encodings.len()) {
                let res = encode!(&buffer, encodings[i]);
                let c = recode!(res, encodings[i], encodings[j]);
                assert_eq!(buffer, decode!(c, encodings[j]));
            }
        }
    }
}
