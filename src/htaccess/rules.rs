use std::{net::IpAddr, path::PathBuf};
use regex::Regex;


#[derive(Debug, Clone)]
pub struct ProxyCmd {
    pub prefix: String,
    pub target: String,
    pub ttl_secs: u64,
    pub command: String,
}

#[derive(Debug, Clone, Default)]
pub struct HtAccess {
    pub auth_basic: bool,
    pub auth_userfile: Option<PathBuf>,
    pub require_valid_user: bool,
    pub allow_ips: Vec<IpAddr>,
    pub deny_ips: Vec<IpAddr>,
    pub require_ips: Vec<IpAddr>,
    pub proxy_pass: Vec<(String, String)>,
    pub proxy_cmd_pass: Vec<ProxyCmd>,

    // NEW
    pub options_indexes: Option<bool>, // Some(true)=enabled, Some(false)=disabled
    pub follow_symlinks: Option<usize>,
    pub allowed_dirs: Vec<PathBuf>,

    pub rewrite_rules: Vec<(Regex, String)>,
    // pub render_mode: RenderMode,
}



