

use clap::Parser;
use std::{fs, path::{Path, PathBuf}};

use usrhttpd::static_handler::generate_directory_html;

#[derive(Parser)]
#[command(name = "usrhttpd-indexgen")]
#[command(about = "Generate static index.html files for directories")]
struct Args {
    /// Root directory
    #[arg(default_value = ".")]
    root: String,

    /// Recurse into subdirectories
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Clobber
    #[arg(short = 'c', long, default_value_t = false)]
    clobber: bool,
}

fn main() {
    let args = Args::parse();

    let root = PathBuf::from(&args.root);

    if !root.is_dir() {
        eprintln!("Not a directory: {}", root.display());
        std::process::exit(1);
    }

    if args.recursive {
        generate_recursive(&root, "/", args.clobber);
    } else {
        generate_single(&root, "/", args.clobber);
    }
}

fn generate_single(dir: &Path, uri_path: &str, clobber: bool) {
    let index_path = dir.join("index.html");
    if index_path.exists() && !clobber {
        eprintln!("Skipped {} (already exists)", index_path.display());
        return;
    }
    match generate_directory_html(&dir.to_path_buf(), uri_path) {
        Ok(html) => {
            println!("Generating {}", index_path.display());

            if let Err(e) = fs::write(index_path, html) {
                eprintln!("Write error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Failed to read {}: {}", dir.display(), e);
        }
    }
}

fn generate_recursive(dir: &Path, uri_path: &str, clobber: bool) {
    generate_single(dir, uri_path, clobber);

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();

            let new_uri = if uri_path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", uri_path, name)
            };

            generate_recursive(&path, &new_uri, clobber);
        }
    }
}
