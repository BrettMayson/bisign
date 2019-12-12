use std::fs::File;
use std::path::PathBuf;

use super::Command;
use crate::{BISignError, BIPublicKey, BISign};

use pbo::PBO;

pub struct Verify {}
impl Command for Verify {
    fn register(&self) -> clap::App {
        clap::App::new("verify")
        .arg(
            clap::Arg::with_name("public")
                .help("Public key to verify with")
                .required(true)
        )
        .arg(
            clap::Arg::with_name("file")
                .help("PBO file to verify")
                .required(true)
        )
        .arg(
            clap::Arg::with_name("signature")
                .help("Signature to verify against")
                .short("s")
        )
    }

    fn run(&self, args: &clap::ArgMatches) -> Result<(), BISignError> {
        let mut publickey_file = File::open(&args.value_of("public").unwrap()).expect("Failed to open public key");
        let publickey = BIPublicKey::read(&mut publickey_file).expect("Failed to read public key");
        let pbo_path = args.value_of("file").unwrap();
        let mut pbo_file = File::open(&pbo_path).expect("Failed to open PBO");
        let mut pbo = PBO::read(&mut pbo_file).expect("Failed to read PBO");

        let sig_path = match args.value_of("signature") {
            Some(path) => PathBuf::from(path),
            None => {
                let mut path = PathBuf::from(pbo_path);
                path.set_extension(format!("pbo.{}.bisign", publickey.name));
                path
            }
        };

        let sig = BISign::read(&mut File::open(&sig_path).expect("Failed to open signature")).expect("Failed to read signature");

        publickey.verify(&mut pbo, &sig)
    }
}