

pub mod args;
pub mod file;
pub mod runtime;

use clap::Parser;

use args::Args;
use file::FileConfig;

pub fn parse() -> Args {
    Args::parse()
}

pub fn load() -> Option<FileConfig> {
    file::load_config()
}

pub fn merge(args: Args, file: Option<FileConfig>) -> Args {
    file::merge_config(args, file)
}

pub fn finalize(args: Args) -> runtime::FinalConfig {
    runtime::FinalConfig::from(args)
}
