

pub mod args;
pub mod file;
pub mod runtime;

use crate::Args;
use file::FileConfig;

pub fn load() -> Option<FileConfig> {
    file::load_config()
}

pub fn merge(args: Args, file: Option<FileConfig>) -> Args {
    file::merge_config(args, file)
}

