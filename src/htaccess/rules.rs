use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Clone, Default)]
pub struct HtAccess {
    pub auth_basic: bool,
    pub auth_userfile: Option<PathBuf>,
    pub require_valid_user: bool,
    pub allow_ips: Vec<IpAddr>,
    pub deny_ips: Vec<IpAddr>,
    pub require_ips: Vec<IpAddr>,
    pub proxy_pass: Vec<(String, String)>,


    // NEW
    pub options_indexes: Option<bool>, // Some(true)=enabled, Some(false)=disabled
    pub follow_symlinks: Option<usize>,
}



