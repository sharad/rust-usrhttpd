

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use crate::Args;



#[derive(Debug, Deserialize)]
pub struct FileConfig {
    pub root: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,

    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
}

pub fn load_config() -> Option<FileConfig> {
    let paths = vec![
        dirs::config_dir()?.join("usrhttpd/config.toml"),
        PathBuf::from("/etc/usrhttpd/config.toml"),
        PathBuf::from("/usr/share/usrhttpd/config.toml"),
    ];

    for path in paths {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str(&content) {
                return Some(cfg);
            }
        }
    }

    None
}



// pub fn merge_config(args: Args, file: Option<FileConfig>) -> Args {
//     if let Some(cfg) = file {
//         Args {
//             root: cfg.root.unwrap_or(args.root),
//             host: cfg.host.unwrap_or(args.host),
//             port: cfg.port.unwrap_or(args.port),

//             tls_cert: cfg.tls.as_ref().and_then(|t| t.cert.clone()).or(args.tls_cert),
//             tls_key: cfg.tls.as_ref().and_then(|t| t.key.clone()).or(args.tls_key),

//             config: args.config,   // 👈 ADD THIS
//         }
//     } else {
//         args
//     }
// }


pub fn merge_config(args: Args, file: Option<FileConfig>) -> Args {
    if let Some(cfg) = file {
        Args {
            root: args.root.or(cfg.root).or(Some("./public".into())),
            host: args.host.or(cfg.host).or(Some("127.0.0.1".into())),
            port: args.port.or(cfg.port).or(Some(8080)),

            tls_cert: args.tls_cert.or(cfg.tls.as_ref().and_then(|t| t.cert.clone())),
            tls_key: args.tls_key.or(cfg.tls.as_ref().and_then(|t| t.key.clone())),

            config: args.config,
        }
    } else {
        args
    }
}
