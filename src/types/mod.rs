mod private_key;
pub use private_key::BIPrivateKey;

mod public_key;
pub use public_key::BIPublicKey;

mod signature;
pub use signature::{BISign, BISignVersion};

use std::io::{Error, Read, Seek, Write};

use openssl::bn::BigNum;
use openssl::hash::{DigestBytes, Hasher, MessageDigest};
use pbo::PBO;

pub fn generate_hashes<I: Seek + Read>(
    pbo: &mut PBO<I>,
    version: BISignVersion,
    length: u32,
) -> (BigNum, BigNum, BigNum) {
    let checksum = pbo.checksum().unwrap();
    let hash1 = checksum.as_slice();

    println!("Hash: {:?}", hash1);

    let mut h = Hasher::new(MessageDigest::sha1()).unwrap();
    h.update(hash1).unwrap();
    let namehashed = &*namehash(pbo);
    println!("Namehash: {:?}", namehashed);
    h.update(&*namehashed).unwrap();
    if let Some(prefix) = pbo.extensions.get("prefix") {
        h.update(prefix.as_bytes()).unwrap();
        if !prefix.ends_with('\\') {
            h.update(b"\\").unwrap();
        }
    }
    let hash2 = &*h.finish().unwrap();

    h = Hasher::new(MessageDigest::sha1()).unwrap();
    let filehashed = filehash(pbo, version);
    println!("Filehash: {:?}", filehashed);
    h.update(&*filehashed).unwrap();
    h.update(&*namehash(pbo)).unwrap();
    if let Some(prefix) = pbo.extensions.get("prefix") {
        h.update(prefix.as_bytes()).unwrap();
        if !prefix.ends_with('\\') {
            h.update(b"\\").unwrap();
        }
    }
    let hash3 = &*h.finish().unwrap();

    println!("H1 {:?}", hash1);
    println!("H2 {:?}", hash2);
    println!("H3 {:?}", hash3);

    (
        pad_hash(hash1, (length / 8) as usize),
        pad_hash(hash2, (length / 8) as usize),
        pad_hash(hash3, (length / 8) as usize),
    )
}

pub fn pad_hash(hash: &[u8], size: usize) -> BigNum {
    let mut vec: Vec<u8> = Vec::new();

    vec.push(0);
    vec.push(1);
    vec.resize(size - 36, 255);
    vec.extend(b"\x00\x30\x21\x30\x09\x06\x05\x2b");
    vec.extend(b"\x0e\x03\x02\x1a\x05\x00\x04\x14");
    vec.extend(hash);

    BigNum::from_slice(&vec).unwrap()
}

pub fn namehash<I: Seek + Read>(pbo: &mut PBO<I>) -> DigestBytes {
    let mut h = Hasher::new(MessageDigest::sha1()).unwrap();

    let files_sorted = pbo.files_sorted(false);

    for header in &files_sorted {
        let data = pbo.retrieve(&header.filename).unwrap();
        if data.get_ref().is_empty() {
            continue;
        }

        h.update(header.filename.to_lowercase().as_bytes()).unwrap();
    }

    h.finish().unwrap()
}

pub fn filehash<I: Seek + Read>(pbo: &mut PBO<I>, version: BISignVersion) -> DigestBytes {
    let mut h = Hasher::new(MessageDigest::sha1()).unwrap();
    let mut nothing = true;

    for header in pbo.files(false).iter() {
        let ext = header.filename.split('.').last().unwrap();
        println!("\t{}", header.filename);
        match version {
            BISignVersion::V2 => {
                if ext == "paa"
                    || ext == "jpg"
                    || ext == "p3d"
                    || ext == "tga"
                    || ext == "rvmat"
                    || ext == "lip"
                    || ext == "ogg"
                    || ext == "wss"
                    || ext == "png"
                    || ext == "rtm"
                    || ext == "pac"
                    || ext == "fxy"
                    || ext == "wrp"
                {
                    continue;
                }
            }
            BISignVersion::V3 => {
                if ext != "sqf"
                    && ext != "inc"
                    && ext != "bikb"
                    && ext != "ext"
                    && ext != "fsm"
                    && ext != "sqm"
                    && ext != "hpp"
                    && ext != "cfg"
                    && ext != "sqs"
                    && ext != "h"
                {
                    continue;
                }
            }
        }
        let cursor = pbo.retrieve(&header.filename).unwrap();
        h.update((&cursor).get_ref()).unwrap();
        println!("== {} =======", header.filename);
        println!("{:?}", String::from_utf8(cursor.bytes().map(|x| x.unwrap()).collect()));
        println!("=============");
        nothing = false;
    }

    match version {
        BISignVersion::V2 => {
            if nothing {
                h.update(b"nothing").unwrap();
            }
        }
        BISignVersion::V3 => {
            if nothing {
                h.update(b"gnihton").unwrap();
            }
        }
    }

    let out = h.finish().unwrap();
    println!("out: {:?}", out);
    out
}

fn display_hashes(a: BigNum, b: BigNum) -> (String, String) {
    let hexa = a.to_hex_str().unwrap().to_lowercase();
    let hexb = b.to_hex_str().unwrap().to_lowercase();

    if hexa.len() != hexb.len() || hexa.len() <= 40 {
        return (hexa, hexb);
    }

    let (paddinga, hasha) = hexa.split_at(hexa.len() - 40);
    let (paddingb, hashb) = hexb.split_at(hexb.len() - 40);

    if paddinga != paddingb {
        (hexa, hexb)
    } else {
        (hasha.to_string(), hashb.to_string())
    }
}

pub fn write_bignum<O: Write>(output: &mut O, bn: &BigNum, size: usize) -> Result<(), Error> {
    let mut vec: Vec<u8> = bn.to_vec();
    vec = vec.iter().rev().cloned().collect();
    vec.resize(size, 0);

    Ok(output.write_all(&vec)?)
}
