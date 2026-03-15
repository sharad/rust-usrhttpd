pub mod reverse;
pub mod websocket;

use crate::htaccess::rules::HtAccess;

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
