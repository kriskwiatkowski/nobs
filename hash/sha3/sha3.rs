// Copyright 2020 Kris Kwiatkowski. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use ::phf::{phf_map, Map};
use digest::Digest;

// OZAPTF: use sponge from RustCrypto

pub enum Sha3Id {
    SHA3_224,
//    SHA3_256,
//    SHA3_384,
//    SHA3_512,
//    SHAKE128,
//    SHAKE256
}

pub struct spongeDesc {
    r: u8,
    d: u8,
    name: String,
    sfx: u8,
}

static SHA3MODE: phf::Map<&'static Sha3Id, spongeDesc> = phf_map! {
    SHA3_224 => Sha3{r: 144, d: 244/8, name: String::from("SHA3-224"), sfx: 0x06},
};

pub struct Sha3 {
    state: [u8; 25],
    desc: spongeDesc,
    is_squezing: bool,
    idx: usize
}

impl Digest for Sha3 {
    fn new() -> Self {

    }
    fn update(&mut self, data: impl AsRef<[u8]>) {
        if (self.is_squezing) {
            return;
        }

        let mut tlen = self.idx + data.len();
        if (tlen < self.desc.r) {

        }
    }

    fn chain(self, data: impl AsRef<[u8]>) -> Self {
    }


    fn finalize(self) -> Output<Self> {

    }

    fn finalize_reset(&mut self) -> Output<Self> {

    }

    fn reset(&mut self) {
        self.idx = 0;
        self.is_squezing = false
    }
    fn output_size() -> usize {
        0
    }
    fn digest(data: &[u8]) -> Output<Self> {

    }
}

impl Sha3 {
    pub fn new(desc: spongeDesc) -> Sha3 {
        Sha3 {
            state: [0; 25],
            spongeDesc: desc,
            is_squezing: false,
            idx: 0
        }
    }

    pub fn sha3_224() -> Sha3 {
        Sha3::new(SHA3MODE[SHA3_224])
    }
}
