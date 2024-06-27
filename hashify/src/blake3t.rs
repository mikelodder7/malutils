use blake2::digest::Output;
use blake2::{
    digest::{
        generic_array::{
            typenum::{U32, U48, U64},
            GenericArray,
        },
        FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update,
    },
    Digest,
};
use std::io::Read;

macro_rules! blake3_impl {
    ($name:ident, $size:expr, $outputsize:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name(blake3::Hasher);

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                let mut output_reader = self.0.finalize_xof();
                output_reader.fill(out);
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                let mut reader = self.0.finalize_xof();
                let _ = reader.read(out);
                self.0.reset();
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = $outputsize;
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                self.0.reset();
            }
        }

        impl Digest for $name {
            fn new() -> Self {
                $name(blake3::Hasher::new())
            }

            fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data.as_ref());
                $name(hasher)
            }

            fn update(&mut self, data: impl AsRef<[u8]>) {
                self.0.update(data.as_ref());
            }

            fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
                let mut hasher = self.0.clone();
                hasher.update(data.as_ref());
                Self(hasher)
            }

            fn finalize(self) -> Output<Self> {
                let mut res = Output::<Self>::default();
                let mut output_reader = self.0.finalize_xof();
                output_reader.fill(&mut res);
                res
            }

            fn finalize_into(self, out: &mut Output<Self>) {
                let mut reader = self.0.finalize_xof();
                let _ = reader.read(out);
            }

            fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
                let mut output = GenericArray::default();
                let mut output_reader = self.0.finalize_xof();
                output_reader.fill(&mut output);

                self.0 = blake3::Hasher::new();
                output
            }

            fn finalize_into_reset(&mut self, out: &mut Output<Self>)
            where
                Self: FixedOutputReset,
            {
                let mut reader = self.0.finalize_xof();
                let _ = reader.read(out);
                self.0.reset();
            }

            fn reset(&mut self) {
                self.0 = blake3::Hasher::new();
            }

            fn output_size() -> usize {
                $size
            }

            fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data.as_ref());
                let mut res = Output::<Self>::default();
                let mut output_reader = hasher.finalize_xof();
                output_reader.fill(&mut res);
                res
            }
        }
    };
}

blake3_impl!(Blake3_256, 32, U32);
blake3_impl!(Blake3_384, 48, U48);
blake3_impl!(Blake3_512, 64, U64);
