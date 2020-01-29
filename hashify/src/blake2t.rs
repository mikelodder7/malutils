#[cfg(target_pointer_width = "64")]
use blake2::VarBlake2b as VarBlake2;
#[cfg(target_pointer_width = "32")]
use blake2::VarBlake2s as VarBlake2;

use blake2::digest::{FixedOutput, Input, Reset, VariableOutput};
use blake2::Digest;
use sha2::digest::generic_array::typenum::{U32, U48};
use sha2::digest::generic_array::GenericArray;

macro_rules! blake2 {
    ($name:ident, $size:expr, $outputsize:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name(VarBlake2);

        impl FixedOutput for $name {
            type OutputSize = $outputsize;

            fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
                let mut res = GenericArray::default();
                self.0.variable_result(|out| res.copy_from_slice(out));
                res
            }
        }

        impl Input for $name {
            fn input<B>(&mut self, data: B)
            where
                B: AsRef<[u8]>,
            {
                self.0.input(data);
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                self.0.reset();
            }
        }

        impl Digest for $name {
            type OutputSize = $outputsize;

            fn new() -> Self {
                $name(VarBlake2::new($size).unwrap())
            }

            fn input<B>(&mut self, data: B)
            where
                B: AsRef<[u8]>,
            {
                self.0.input(data);
            }

            fn chain<B>(self, data: B) -> Self
            where
                B: AsRef<[u8]>,
            {
                let mut b = self.0.clone();
                b.input(data);
                $name(b)
            }

            fn result(self) -> GenericArray<u8, Self::OutputSize> {
                let mut res = GenericArray::default();
                self.0.variable_result(|out| res.copy_from_slice(out));
                res
            }

            fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
                let b = self.0.clone();
                let mut res = GenericArray::default();
                b.variable_result(|out| res.copy_from_slice(out));
                self.0.reset();
                res
            }

            fn reset(&mut self) {
                self.0.reset();
            }

            fn output_size() -> usize {
                $size
            }

            fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
                let mut res = GenericArray::default();
                let mut b = VarBlake2::new($size).unwrap();
                b.input(data);
                b.variable_result(|out| res.copy_from_slice(out));
                res
            }
        }
    };
}

blake2!(Blake2_256, 32, U32);
blake2!(Blake2_384, 48, U48);
