

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use super::args::Args;



#[derive(Debug, Deserialize)]
pub struct FileConfig {
    pub root: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<TlsConfig>,
    pub alog: Option<String>,
    pub log: Option<String>,
    pub inetd: Option<bool>,
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

pub fn merge_config(args: Args, file: Option<FileConfig>) -> Args {
    if let Some(cfg) = file {
        Args {
            root: expand_opt(
                args.root.or(cfg.root).or(Some("./public".into()))
            ),

            host: args.host.or(cfg.host).or(Some("127.0.0.1".into())),

            port: args.port.or(cfg.port).or(Some(8080)),

            tls_cert: expand_opt(
                args.tls_cert.or(
                    cfg.tls.as_ref().and_then(|t| t.cert.clone())
                )
            ),

            tls_key: expand_opt(
                args.tls_key.or(
                    cfg.tls.as_ref().and_then(|t| t.key.clone())
                )
            ),

            alog: expand_opt(
                args.alog.or(cfg.alog).or(Some("access.log".into()))
            ),

            log: expand_opt(
                args.log.or(cfg.log).or(Some("error.log".into()))
            ),

            inetd: args.inetd.or(cfg.inetd).or(Some(false)),

            config: expand_opt(args.config),
        }
    } else {
        args
    }
}

fn expand_opt(v: Option<String>) -> Option<String> {
    v.map(|s| {
        shellexpand::full(&s)
            .unwrap_or_else(|_| std::borrow::Cow::Owned(s.clone()))
            .into_owned()
    })
}
