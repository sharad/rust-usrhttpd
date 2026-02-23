use super::rules::HtAccess;
use std::net::IpAddr;

pub fn check(r: &HtAccess, remote: Option<IpAddr>) -> bool {
    if let Some(ip) = remote {
        if r.deny_ips.contains(&ip) {
            return false;
        }

        if !r.allow_ips.is_empty() {
            return r.allow_ips.contains(&ip);
        }

        if !r.require_ips.is_empty() {
            return r.require_ips.contains(&ip);
        }
    }

    true
}


