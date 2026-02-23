use base64::{engine::general_purpose, Engine};
use sha1::{Digest, Sha1};
use std::fs;

use super::rules::HtAccess;

pub fn check(r: &HtAccess, header: Option<&str>) -> bool {
    if !r.auth_basic || !r.require_valid_user {
        return true;
    }

    let header = match header {
        Some(h) if h.starts_with("Basic ") => &h[6..],
        _ => return false,
    };

    let decoded = general_purpose::STANDARD.decode(header).ok();
    let decoded = match decoded {
        Some(v) => String::from_utf8_lossy(&v).to_string(),
        None => return false,
    };

    let mut parts = decoded.splitn(2, ':');
    let user = parts.next().unwrap_or("");
    let pass = parts.next().unwrap_or("");

    let file = match &r.auth_userfile {
        Some(p) => p,
        None => return false,
    };

    // let content = fs::read_to_string(file).ok()?;
    let content = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for line in content.lines() {
        if let Some((u, p)) = line.split_once(':') {
            if u == user {
                if p.starts_with("{SHA}") {
                    let mut hasher = Sha1::new();
                    hasher.update(pass.as_bytes());
                    let hash = general_purpose::STANDARD.encode(hasher.finalize());
                    if format!("{{SHA}}{}", hash) == p {
                        return true;
                    }
                } else if p == pass {
                    return true;
                }
            }
        }
    }

    false
}


