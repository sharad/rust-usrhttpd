

pub mod cmd;
pub mod reverse;
pub mod websocket;
pub mod http_client;

use crate::htaccess::rules::HtAccess;
use crate::htaccess::rules::ProxyCmd;

// pub fn match_proxy(r: &HtAccess, path: &str) -> Option<(String, String)> {
//     for (prefix, target) in &r.proxy_pass {
//         if path.starts_with(prefix) {
//             return Some((prefix.clone(), target.clone()));
//         }
//     }
//     None
// }


pub fn match_proxy(r: &HtAccess, path: &str) -> Option<(String,String)> {
    r.proxy_pass
        .iter()
        .filter(|(prefix, _)| path.starts_with(prefix))
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(p,t)| (p.clone(), t.clone()))
}





pub fn match_proxy_cmd(
        r: &HtAccess,
        path: &str,
) -> Option<ProxyCmd> {

        r.proxy_cmd_pass
                .iter()
                .filter(|c| path.starts_with(&c.prefix))
                .max_by_key(|c| c.prefix.len())
                .cloned()
}

