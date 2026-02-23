
use parking_lot::RwLock;
use regex::Regex;
use reqwest::Client;
use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::fs::read_to_string;
use warp::{
    http::{HeaderMap, Method, StatusCode},
    hyper::Body,
    path::FullPath,
    reply::Response,
    Filter, Rejection, Reply,
};

/// Simple in-memory cache of parsed .htaccess per directory
type Cache = Arc<RwLock<HashMap<PathBuf, HtAccess>>>;

/// Minimal rule set parsed from .htaccess
#[derive(Debug, Default, Clone)]
struct HtAccess {
    auth_basic: bool,
    auth_userfile: Option<PathBuf>,
    require_valid_user: bool,
    require_ips: Vec<IpAddr>,   // require specific IPs
    allow_ips: Vec<IpAddr>,     // allow
    deny_ips: Vec<IpAddr>,      // deny
    proxy_pass: Vec<(String, String)>, // (prefix, target_url)
}

/// Parse a single .htaccess file content into HtAccess (very small subset)
fn parse_htaccess(contents: &str, base_dir: &Path) -> HtAccess {
    let mut h = HtAccess::default();
    let ip_re = Regex::new(r"(\d{1,3}(\.\d{1,3}){3})").unwrap();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(cmd) = parts.get(0) {
            let cmd = cmd.to_ascii_lowercase();
            // match parts.get(0).map(|s| s.to_lowercase().as_str()) {
            match cmd.as_str() {
                Some("authtype") => {
                    if parts.get(1).map(|s| s.to_lowercase()) == Some("basic".to_string()) {
                        h.auth_basic = true;
                    }
                }
                Some("authuserfile") => {
                    if let Some(p) = parts.get(1) {
                        let p = PathBuf::from(p);
                        let p = if p.is_relative() { base_dir.join(p) } else { p };
                        h.auth_userfile = Some(p);
                    }
                }
                Some("require") => {
                    // Accept "require valid-user" or "require ip 1.2.3.4"
                    if let Some(arg) = parts.get(1) {
                        if arg.to_lowercase() == "valid-user" {
                            h.require_valid_user = true;
                        } else if arg.to_lowercase() == "ip" {
                            if let Some(ip_s) = parts.get(2) {
                                if let Ok(ip) = ip_s.parse() {
                                    h.require_ips.push(ip);
                                }
                            }
                        }
                    }
                }
                Some("allow") => {
                    // Allow from 1.2.3.4
                    if parts.get(1).map(|s| s.to_lowercase().as_str()) == Some("from") {
                        if let Some(ip_s) = parts.get(2) {
                            if let Ok(ip) = ip_s.parse() {
                                h.allow_ips.push(ip);
                            }
                        }
                    } else if let Some(mat) = ip_re.find(line) {
                        if let Ok(ip) = mat.as_str().parse() {
                            h.allow_ips.push(ip);
                        }
                    }
                }
                Some("deny") => {
                    // Deny from x.x.x.x
                    if parts.get(1).map(|s| s.to_lowercase().as_str()) == Some("from") {
                        if let Some(ip_s) = parts.get(2) {
                            if let Ok(ip) = ip_s.parse() {
                                h.deny_ips.push(ip);
                            }
                        }
                    } else if let Some(mat) = ip_re.find(line) {
                        if let Ok(ip) = mat.as_str().parse() {
                            h.deny_ips.push(ip);
                        }
                    }
                }
                Some("proxypass") => {
                    // ProxyPass /prefix http://backend:port/
                    if let (Some(prefix), Some(target)) = (parts.get(1), parts.get(2)) {
                        h.proxy_pass.push((prefix.to_string(), target.to_string()));
                    }
                }
                _ => {}
            }
        }
    }
    h
}

/// Walk up from the requested filesystem path directory to the root_dir
/// collecting/merging .htaccess files (child overrides parent if needed).
async fn collect_htaccess_for_path(
    fs_path: &Path,
    root_dir: &Path,
    cache: &Cache,
) -> HtAccess {
    let mut combined = HtAccess::default();
    // Start at fs_path dir (if fs_path is file, use parent)
    let mut cur = if fs_path.is_dir() {
        fs_path.to_path_buf()
    } else {
        fs_path.parent().unwrap_or(root_dir).to_path_buf()
    };
    loop {
        if !cur.starts_with(root_dir) {
            break;
        }
        let ht = cur.join(".htaccess");
        // Try cache
        let parsed_opt = {
            let map = cache.read();
            map.get(&cur).cloned()
        };
        let parsed = if let Some(p) = parsed_opt {
            p
        } else if ht.exists() {
            match read_to_string(&ht).await {
                Ok(contents) => {
                    let parsed = parse_htaccess(&contents, &cur);
                    let mut map = cache.write();
                    map.insert(cur.clone(), parsed.clone());
                    parsed
                }
                Err(_) => HtAccess::default(),
            }
        } else {
            HtAccess::default()
        };
        // Merge parsed into combined (simple append semantics)
        if parsed.auth_basic {
            combined.auth_basic = true;
        }
        if parsed.auth_userfile.is_some() {
            combined.auth_userfile = parsed.auth_userfile.clone();
        }
        combined.require_valid_user |= parsed.require_valid_user;
        combined.require_ips.extend(parsed.require_ips.clone());
        combined.allow_ips.extend(parsed.allow_ips.clone());
        combined.deny_ips.extend(parsed.deny_ips.clone());
        combined.proxy_pass.extend(parsed.proxy_pass.clone());
        if cur == root_dir {
            break;
        }
        if let Some(parent) = cur.parent() {
            cur = parent.to_path_buf();
        } else {
            break;
        }
    }
    combined
}

/// Very small function to verify Basic Auth header against a plain htpasswd file
/// Format expected: each line `username:password` (plaintext) — replace with hashed verification in production
fn verify_basic_auth(header: Option<&str>, userfile: &Path) -> Result<Option<String>, anyhow::Error> {
    let header = match header {
        Some(h) => h,
        None => return Ok(None),
    };
    if !header.to_lowercase().starts_with("basic ") {
        return Ok(None);
    }
    let b64 = header[6..].trim();
    let decoded = base64::decode(b64)?;
    let decoded = String::from_utf8_lossy(&decoded);
    let mut parts = decoded.splitn(2, ':');
    let user = parts.next().unwrap_or("").to_string();
    let pass = parts.next().unwrap_or("");
    let content = fs::read_to_string(userfile)?;
    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((u, p)) = l.split_once(':') {
            if u == user && p == pass {
                return Ok(Some(user));
            }
        }
    }
    Ok(None)
}

/// Check IP allow/deny rules against remote IP
fn check_ip_rules(rules: &HtAccess, remote: Option<IpAddr>) -> bool {
    // Deny rules take precedence
    if let Some(ip) = remote {
        if rules.deny_ips.iter().any(|d| *d == ip) {
            return false;
        }
        // If allow list present, enforce it
        if !rules.allow_ips.is_empty() {
            return rules.allow_ips.iter().any(|a| *a == ip);
        }
        // If require_ips present, require match
        if !rules.require_ips.is_empty() {
            return rules.require_ips.iter().any(|a| *a == ip);
        }
    } else {
        // No remote address — be conservative: if allow list is empty, permit; else deny
        if !rules.allow_ips.is_empty() || !rules.require_ips.is_empty() {
            return false;
        }
    }
    true
}

/// Try to match proxy rules. Returns Some(target_url) if matched.
fn match_proxy(rules: &HtAccess, uri_path: &str) -> Option<String> {
    for (prefix, target) in &rules.proxy_pass {
        if uri_path.starts_with(prefix) {
            // Build target by appending remainder
            let remainder = &uri_path[prefix.len()..];
            let mut target = target.clone();
            if !target.ends_with('/') && !remainder.is_empty() {
                target.push('/');
            }
            target.push_str(remainder.trim_start_matches('/'));
            return Some(target);
        }
    }
    None
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Configuration
    let root_dir = PathBuf::from("./public"); // serve files from ./public
    let listen_addr = ([127, 0, 0, 1], 8080);

    // Shared cache
    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));
    let client = Client::builder().danger_accept_invalid_certs(true).build().unwrap();

    // Filters
    let root = warp::any().map(move || root_dir.clone());
    let cache_filter = warp::any().map(move || cache.clone());
    let client_filter = warp::any().map(move || client.clone());

    // FullPath gives the original path (including leading slash)
    let route = warp::any()
        .and(warp::method())
        .and(warp::addr::remote())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::path::full())
        .and(warp::query::raw().or_else(|_| async { Ok::<(String,), Rejection>((String::new(),)) }))
        .and(root)
        .and(cache_filter)
        .and(client_filter)
        .and_then(
            |method: Method,
             remote: Option<std::net::SocketAddr>,
             auth_header: Option<String>,
             full: FullPath,
             _query: String,
             root_dir: PathBuf,
             cache: Cache,
             client: Client| async move {
                // Map request path to filesystem path under root_dir
                let uri_path = full.as_str();
                let rel_path = uri_path.trim_start_matches('/');
                let fs_path = root_dir.join(rel_path);

                // Collect combined rules from .htaccess hierarchy
                let rules = collect_htaccess_for_path(&fs_path, &root_dir, &cache).await;

                // 1) IP checks
                let remote_ip = remote.map(|r| r.ip());
                if !check_ip_rules(&rules, remote_ip) {
                    return Ok::<_, Rejection>(warp::reply::with_status(
                        "Forbidden (IP)",
                        StatusCode::FORBIDDEN,
                    )
                    .into_response());
                }

                // 2) Proxy handling
                if let Some(target) = match_proxy(&rules, uri_path) {
                    // forward request (simple GET/POST preserve body not implemented in this tiny demo)
                    let resp = client.get(&target).send().await;
                    match resp {
                        Ok(mut r) => {
                            let status = r.status();
                            let headers = r.headers().clone();
                            let bytes = r.bytes().await.unwrap_or_default();
                            let mut res = Response::new(Body::from(bytes));
                            *res.status_mut() = status;
                            // copy a few headers (not all)
                            for (k, v) in headers.iter() {
                                res.headers_mut().insert(k.clone(), v.clone());
                            }
                            return Ok::<_, Rejection>(res);
                        }
                        Err(e) => {
                            tracing::error!("proxy error: {}", e);
                            return Ok::<_, Rejection>(warp::reply::with_status(
                                "Bad Gateway",
                                StatusCode::BAD_GATEWAY,
                            )
                            .into_response());
                        }
                    }
                }

                // 3) Authentication
                if rules.auth_basic && rules.require_valid_user {
                    if let Some(userfile) = rules.auth_userfile.clone() {
                        // verify header
                        match verify_basic_auth(auth_header.as_deref(), &userfile) {
                            Ok(Some(_user)) => {
                                // ok
                            }
                            Ok(None) => {
                                // challenge
                                let mut res = warp::reply::with_status("Unauthorized", StatusCode::UNAUTHORIZED)
                                    .into_response();
                                res.headers_mut().insert(
                                    "WWW-Authenticate",
                                    "Basic realm=\"Restricted\"".parse().unwrap(),
                                );
                                return Ok::<_, Rejection>(res);
                            }
                            Err(_) => {
                                // error reading userfile
                                return Ok::<_, Rejection>(warp::reply::with_status(
                                    "Server Error",
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                )
                                .into_response());
                            }
                        }
                    } else {
                        return Ok::<_, Rejection>(warp::reply::with_status(
                            "Server misconfigured: missing AuthUserFile",
                            StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response());
                    }
                }

                // 4) Serve static file (or index.html if directory)
                // If path is directory, serve index.html or list not implemented (keep simple)
                let file_path = if fs_path.is_dir() {
                    fs::canonicalize(fs_path.join("index.html")).unwrap_or(root_dir.join("index.html"))
                } else {
                    fs::canonicalize(&fs_path).unwrap_or(root_dir.join("index.html"))
                };

                // Security: ensure file_path still under root_dir (prevent directory traversal)
                if !file_path.starts_with(&root_dir) {
                    return Ok::<_, Rejection>(warp::reply::with_status(
                        "Forbidden",
                        StatusCode::FORBIDDEN,
                    )
                    .into_response());
                }

                match tokio::fs::read(file_path).await {
                    Ok(bytes) => {
                        // simple content-type detection
                        let mime = mime_guess::from_path(rel_path).first_or_octet_stream();
                        let mut resp = Response::new(Body::from(bytes));
                        resp.headers_mut().insert("content-type", mime.to_string().parse().unwrap());
                        return Ok::<_, Rejection>(resp);
                    }
                    Err(_) => {
                        return Ok::<_, Rejection>(warp::reply::with_status(
                            "Not Found",
                            StatusCode::NOT_FOUND,
                        )
                        .into_response());
                    }
                }
            },
        );

    // println!("Listening on http://{}:{}", listen_addr.0, listen_addr.1);
    println!(
        "Listening on http://{}.{}.{}.{}:{}",
        listen_addr.0[0],
        listen_addr.0[1],
        listen_addr.0[2],
        listen_addr.0[3],
        listen_addr.1
    );
    warp::serve(route).run(listen_addr).await;
}


