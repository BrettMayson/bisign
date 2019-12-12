use std::collections::HashMap;

mod commands;
pub use commands::Command;

mod types;
pub use types::{BIPrivateKey, BIPublicKey, BISign, BISignVersion};

mod error;
pub use error::BISignError;

lazy_static::lazy_static! {
    pub static ref VERSION: &'static str = {
        let mut version = env!("CARGO_PKG_VERSION").to_string();
        if let Some(v) = option_env!("GIT_HASH") {
            version.push_str("-");
            version.push_str(v);
        }
        if cfg!(debug_assertions) {
            version.push_str("-debug");
        }
        Box::leak(Box::new(version))
    };
}

pub fn execute(input: &[String]) -> Result<(), BISignError> {
    let mut app = clap::App::new("bisign")
        .version(*crate::VERSION)
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            clap::Arg::with_name("debug")
                .global(true)
                .help("Turn on debugging information")
                .long("debug"),
        );

    let mut commands: Vec<Box<dyn Command>> = Vec::new();
    let mut hash_commands: HashMap<String, &Box<dyn Command>> = HashMap::new();

    // Add commands here
    commands.push(Box::new(commands::Keygen {}));
    commands.push(Box::new(commands::Sign {}));
    commands.push(Box::new(commands::Verify {}));

    for command in commands.iter() {
        let sub = command.register();
        hash_commands.insert(sub.get_name().to_owned(), command);
        app = app.subcommand(sub);
    }

    let mut help: Vec<u8> = Vec::new();
    app.write_help(&mut help).unwrap();

    let matches = app.get_matches_from(input);
    match matches.subcommand_name() {
        Some(v) => match hash_commands.get(v) {
            Some(c) => {
                c.run(matches.subcommand_matches(v).unwrap())?;
            }
            None => println!("No command"),
        },
        None => {
            println!("{}", String::from_utf8(help).unwrap());
        },
    }

    Ok(())
}
