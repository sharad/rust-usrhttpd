// src/config/final.rs

use super::args::Args;

pub struct FinalConfig {
    pub root: String,
    pub host: String,
    pub port: u16,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub alog: Option<String>,
    pub log: Option<String>,
    pub inetd: Option<bool>,
}

impl From<Args> for FinalConfig {
    fn from(args: Args) -> Self {
        FinalConfig {
            root: args.root.unwrap(),
            host: args.host.unwrap(),
            port: args.port.unwrap(),
            tls_cert: args.tls_cert,
            tls_key: args.tls_key,
            alog: args.alog,
            log: args.log,
            inetd: args.inetd,
        }
    }
}





