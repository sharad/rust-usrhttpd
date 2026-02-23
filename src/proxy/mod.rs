pub mod reverse;
pub mod websocket;

use crate::htaccess::rules::HtAccess;

pub fn match_proxy(r: &HtAccess, path: &str) -> Option<String> {
    for (prefix, target) in &r.proxy_pass {
        if path.starts_with(prefix) {
            return Some(target.clone());
        }
    }
    None
}

