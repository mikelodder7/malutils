use blake2::digest::{FixedOutput, Input, Reset};
use blake2::Digest;
use sha2::digest::generic_array::typenum::{U32, U48, U64};
use sha2::digest::generic_array::GenericArray;

macro_rules! blake3_impl {
    ($name:ident, $size:expr, $outputsize:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name(blake3::Hasher);

        impl FixedOutput for $name {
            type OutputSize = $outputsize;

            fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
                let mut output = [0u8; $size];
                let mut output_reader = self.0.finalize_xof();
                output_reader.fill(&mut output);

                let mut res = GenericArray::default();
                res.copy_from_slice(&output[..]);
                res
            }
        }

        impl Input for $name {
            fn input<B>(&mut self, data: B)
            where
                B: AsRef<[u8]>,
            {
                self.0.update(data.as_ref());
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                self.0 = blake3::Hasher::new();
            }
        }

        impl Digest for $name {
            type OutputSize = $outputsize;

            fn new() -> Self {
                $name(blake3::Hasher::new())
            }

            fn input<B>(&mut self, data: B)
            where
                B: AsRef<[u8]>,
            {
                self.0.update(data.as_ref());
            }

            fn chain<B>(self, data: B) -> Self
            where
                B: AsRef<[u8]>,
            {
                let mut b = self.0.clone();
                b.update(data.as_ref());
                $name(b)
            }

            fn result(self) -> GenericArray<u8, Self::OutputSize> {
                let mut output = [0u8; $size];
                let mut output_reader = self.0.finalize_xof();
                output_reader.fill(&mut output);

                let mut res = GenericArray::default();
                res.copy_from_slice(&output[..]);
                res
            }

            fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
                let mut output = [0u8; $size];
                let mut output_reader = self.0.finalize_xof();
                output_reader.fill(&mut output);

                self.0 = blake3::Hasher::new();
                let mut res = GenericArray::default();
                res.copy_from_slice(&output[..]);
                res
            }

            fn reset(&mut self) {
                self.0 = blake3::Hasher::new();
            }

            fn output_size() -> usize {
                $size
            }

            fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                let mut output = [0u8; $size];
                let mut output_reader = hasher.finalize_xof();
                output_reader.fill(&mut output);
                let mut res = GenericArray::default();
                res.copy_from_slice(&output[..]);
                res
            }
        }
    };
}

blake3_impl!(Blake3_256, 32, U32);
blake3_impl!(Blake3_384, 48, U48);
blake3_impl!(Blake3_512, 64, U64);
