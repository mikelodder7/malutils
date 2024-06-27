#[cfg(target_pointer_width = "64")]
use blake2::Blake2bVar as VarBlake2;
#[cfg(target_pointer_width = "32")]
use blake2::Blake2sVar as VarBlake2;

use blake2::digest::Output;
use blake2::{
    digest::{
        generic_array::typenum::{U32, U48},
        FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update, VariableOutput,
    },
    Digest,
};

macro_rules! blake2 {
    ($name:ident, $size:expr, $outputsize:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name(VarBlake2);

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                self.0.finalize_variable(out).expect("invalid output size");
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                self.0
                    .clone()
                    .finalize_variable(out)
                    .expect("reader read failed");
                <Self as Reset>::reset(self);
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
                self.0 = VarBlake2::new($size).unwrap();
            }
        }

        impl Digest for $name {
            fn new() -> Self {
                $name(VarBlake2::new($size).unwrap())
            }

            fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
                let mut hasher = Self::new();
                hasher.0.update(data.as_ref());
                hasher
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
                self.0.finalize_variable(&mut res).expect("finalize failed");
                res
            }

            fn finalize_reset(&mut self) -> Output<Self>
            where
                Self: FixedOutputReset,
            {
                let mut res = Output::<Self>::default();
                self.0
                    .clone()
                    .finalize_variable(&mut res)
                    .expect("finalize failed");
                <Self as Reset>::reset(self);
                res
            }

            fn finalize_into(self, out: &mut Output<Self>) {
                self.0.finalize_variable(out).expect("finalize failed");
            }

            fn reset(&mut self) {
                self.0 = VarBlake2::new($size).unwrap();
            }

            fn finalize_into_reset(&mut self, out: &mut Output<Self>)
            where
                Self: FixedOutputReset,
            {
                self.0
                    .clone()
                    .finalize_variable(out)
                    .expect("finalize failed");
                <Self as Reset>::reset(self)
            }

            fn output_size() -> usize {
                $size
            }

            fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
                let mut res = Output::<Self>::default();
                let mut b = Self::new();
                <Self as Digest>::update(&mut b, data);
                <Self as FixedOutput>::finalize_into(b, &mut res);
                res
            }
        }
    };
}

blake2!(Blake2_256, 32, U32);
blake2!(Blake2_384, 48, U48);
