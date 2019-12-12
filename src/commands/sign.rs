use std::fs::File;
use std::path::PathBuf;

use super::Command;
use crate::{BISignError, BIPrivateKey};

use pbo::PBO;

pub struct Sign {}
impl Command for Sign {
    fn register(&self) -> clap::App {
        clap::App::new("sign")
        .arg(
            clap::Arg::with_name("private")
                .help("Private key to sign with")
                .required(true)
        )
        .arg(
            clap::Arg::with_name("file")
                .help("PBO file to sign")
                .required(true)
        )
        .arg(
            clap::Arg::with_name("out")
                .help("Output location of signature")
                .short("o")
                .takes_value(true)
        )
        .arg(
            clap::Arg::with_name("version")
                .help("BISignVersion")
                .default_value("3")
                .possible_values(&["2","3"])
                .short("v")
        )
    }

    fn run(&self, args: &clap::ArgMatches) -> Result<(), BISignError> {
        let pbo_path = args.value_of("file").unwrap();
        let privatekey = BIPrivateKey::read(&mut File::open(args.value_of("private").unwrap()).expect("Failed to open private key")).expect("Failed to read private key");
        let mut pbo_file = File::open(&pbo_path).expect("Failed to open PBO");
        let mut pbo = PBO::read(&mut pbo_file).expect("Failed to read PBO");

        let sig_path = match args.value_of("out") {
            Some(path) => PathBuf::from(path),
            None => {
                let mut path = PathBuf::from(pbo_path);
                path.set_extension(format!("pbo.{}.bisign", privatekey.name));
                path
            }
        };

        let sig = privatekey.sign(&mut pbo, args.value_of("version").unwrap().parse::<u32>().unwrap().into());
        sig.write(&mut File::create(&sig_path).expect("Failed to open signature file")).expect("Failed to write signature");

        Ok(())
    }
}