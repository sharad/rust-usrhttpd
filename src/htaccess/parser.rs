use super::rules::HtAccess;
use std::{net::IpAddr, path::{Path, PathBuf}};

pub fn parse(contents: &str, base: &Path) -> HtAccess {
    let mut h = HtAccess::default();

    for line in contents.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue; }

        let parts: Vec<&str> = l.split_whitespace().collect();
        let cmd = parts.get(0).map(|s| s.to_ascii_lowercase());

        match cmd.as_deref() {
            Some("authtype") => {
                if parts.get(1).map(|v| v.eq_ignore_ascii_case("basic")) == Some(true) {
                    h.auth_basic = true;
                }
            }
            Some("authuserfile") => {
                if let Some(p) = parts.get(1) {
                    let path = PathBuf::from(p);
                    h.auth_userfile = Some(
                        if path.is_relative() { base.join(path) } else { path }
                    );
                }
            }
            Some("require") => {
                if let Some(arg) = parts.get(1) {
                    if arg.eq_ignore_ascii_case("valid-user") {
                        h.require_valid_user = true;
                    } else if arg.eq_ignore_ascii_case("ip") {
                        if let Some(ip) = parts.get(2) {
                            if let Ok(addr) = ip.parse::<IpAddr>() {
                                h.require_ips.push(addr);
                            }
                        }
                    }
                }
            }
            Some("allow") => {
                if parts.get(1).map(|v| v.eq_ignore_ascii_case("from")) == Some(true) {
                    if let Some(ip) = parts.get(2) {
                        if let Ok(addr) = ip.parse() {
                            h.allow_ips.push(addr);
                        }
                    }
                }
            }
            Some("deny") => {
                if parts.get(1).map(|v| v.eq_ignore_ascii_case("from")) == Some(true) {
                    if let Some(ip) = parts.get(2) {
                        if let Ok(addr) = ip.parse() {
                            h.deny_ips.push(addr);
                        }
                    }
                }
            }
            Some("proxypass") => {
                if let (Some(prefix), Some(target)) = (parts.get(1), parts.get(2)) {
                    h.proxy_pass.push((prefix.to_string(), target.to_string()));
                }
            }
            Some("options") => {
                if let Some(opt) = parts.get(1) {
                    match *opt {
                        "+Indexes" | "+indexes" => {
                            h.options_indexes = Some(true);
                        }
                        "-Indexes" | "-indexes" => {
                            h.options_indexes = Some(false);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    h
}


