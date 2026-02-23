use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::cache::{HtCache, Cached};
use super::{parser, rules::HtAccess};

pub async fn resolve(root: &Path, uri_path: &str, cache: &HtCache) -> HtAccess {
    let mut result = HtAccess::default();

    let mut dir = root.join(uri_path.trim_start_matches('/'));

    if dir.is_file() {
        if let Some(p) = dir.parent() {
            dir = p.to_path_buf();
        }
    }

    loop {
        if !dir.starts_with(root) {
            break;
        }

        let htfile = dir.join(".htaccess");

        if htfile.exists() {
            let metadata = fs::metadata(&htfile).ok();
            let mtime = metadata.and_then(|m| m.modified().ok());

            if let Some(mtime) = mtime {
                let cached = cache.get(&dir);

                let rules = match cached {
                    Some(c) if c.mtime == mtime => c.rules,
                    _ => {
                        let content = fs::read_to_string(&htfile).unwrap_or_default();
                        let parsed = parser::parse(&content, &dir);
                        cache.insert(dir.clone(), Cached { mtime, rules: parsed.clone() });
                        parsed
                    }
                };

                merge(&mut result, &rules);
            }
        }

        if dir == root {
            break;
        }

        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }

    result
}

fn merge(base: &mut HtAccess, new: &HtAccess) {
    if new.auth_basic {
        base.auth_basic = true;
    }

    if new.auth_userfile.is_some() {
        base.auth_userfile = new.auth_userfile.clone();
    }

    base.require_valid_user |= new.require_valid_user;
    base.allow_ips.extend(new.allow_ips.clone());
    base.deny_ips.extend(new.deny_ips.clone());
    base.require_ips.extend(new.require_ips.clone());
    base.proxy_pass.extend(new.proxy_pass.clone());
}


