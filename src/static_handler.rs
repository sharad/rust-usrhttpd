
use hyper::{Response, StatusCode};
use bytes::Bytes;
use mime_guess::from_path;
use std::{path::PathBuf, fs};
use http_body_util::{Full, BodyExt};
use std::ffi::OsStr;
use std::process::Command;
use pulldown_cmark::{Parser, html};

use crate::types::RespBody;
use crate::htaccess::rules::HtAccess;

pub fn serve(root: &PathBuf, path: &str, rules: &HtAccess,) -> Response<RespBody> {
    let requested = root.join(path.trim_start_matches('/'));
    let levels = rules.follow_symlinks.unwrap_or(10);
    let boundary = root
        .ancestors()
        .nth(levels)
        .unwrap_or(&root)
        .to_path_buf();
    let boundary = match fs::canonicalize(&boundary) {
        Ok(b) => b,
        Err(_) => return resp(StatusCode::INTERNAL_SERVER_ERROR, "Server misconfiguration"),
    };

    eprintln!("root: {}", root.display());
    eprint!("Serving static: boundary={}\n", boundary.display());

    let p = match fs::canonicalize(&requested) {
        Ok(v) => {
            eprint!("Serving static: requested={}\n", requested.display());
            eprintln!("Resolved path: {:?}\n", v);
            // if !v.starts_with(&boundary) {
            //     return resp(StatusCode::FORBIDDEN, "Forbidden");
            // }
            v
        }
        Err(_) => return resp(StatusCode::FORBIDDEN, "Forbidden"),
    };

    // 🔹 If directory → try index files
    if p.is_dir() {
        if let Some(index) = find_index(&p) {
            return serve_file(index);
        }

        // Directory listing control via htaccess
        let allow_listing = rules.options_indexes.unwrap_or(true);

        if !allow_listing {
            return resp(StatusCode::FORBIDDEN, "Directory listing denied");
        }

        return directory_listing(&p, path);
    }

    // 🔹 Normal file
    serve_file(p)
}

fn find_index(dir: &PathBuf) -> Option<PathBuf> {
    for name in ["index.html", "index.htm", "index.md"] {
        let path = dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

fn serve_file(path: PathBuf) -> Response<RespBody> {

    if let Some(resp) = render_if_needed(&path) {
        resp
    } else {
        match fs::read(&path) {
            Ok(bytes) => {
                let mime = from_path(&path).first_or_octet_stream();

                let mut r = Response::new(
                    Full::new(Bytes::from(bytes))
                        .map_err(|never| match never {})
                        .boxed()
                );

                r.headers_mut()
                    .insert("content-type", mime.to_string().parse().unwrap());

                r
            }
            Err(_) => resp(StatusCode::NOT_FOUND, "Not Found"),
        }
    }
}

fn directory_listing(dir: &PathBuf, uri_path: &str) -> Response<RespBody> {
    let mut entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return resp(StatusCode::FORBIDDEN, "Forbidden"),
    };

    let mut html = String::new();

    html.push_str("<html><head><title>Index of ");
    html.push_str(uri_path);
    html.push_str("</title></head><body>");
    html.push_str("<h1>Index of ");
    html.push_str(uri_path);
    html.push_str("</h1><hr><ul>");

    // ----------------------------
    // Parent directory link
    // ----------------------------
    if uri_path != "/" {
        let parent = if uri_path.ends_with('/') {
            uri_path.trim_end_matches('/')
        } else {
            uri_path
        };

        let parent = match parent.rfind('/') {
            Some(0) | None => "/",
            Some(pos) => &parent[..pos + 1],
        };

        html.push_str("<li><a href=\"");
        html.push_str(parent);
        html.push_str("\">../</a></li>");
    }

    // ----------------------------
    // Directory entries
    // ----------------------------
    while let Some(Ok(entry)) = entries.next() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        let display = if entry.path().is_dir() {
            format!("{}/", name)
        } else {
            name.to_string()
        };

        html.push_str("<li><a href=\"");
        html.push_str(&display);
        html.push_str("\">");
        html.push_str(&display);
        html.push_str("</a></li>");
    }

    html.push_str("</ul><hr></body></html>");

    let mut r = Response::new(
        Full::new(Bytes::from(html))
            .map_err(|never| match never {})
            .boxed()
    );

    r.headers_mut()
        .insert("content-type", "text/html".parse().unwrap());

    r
}


fn resp(code: StatusCode, body: &str) -> Response<RespBody> {
    Response::builder()
        .status(code)
        .body(
            Full::new(Bytes::from(body.to_string()))
                .map_err(|never| match never {})
                .boxed()
        )
        .unwrap()
}

pub fn forbidden() -> Response<RespBody> {
    resp(StatusCode::FORBIDDEN, "Forbidden")
}

pub fn auth_required() -> Response<RespBody> {
    let mut r = resp(StatusCode::UNAUTHORIZED, "Unauthorized");
    r.headers_mut().insert(
        "WWW-Authenticate",
        "Basic realm=\"Restricted\"".parse().unwrap(),
    );
    r
}



///


fn html_response(html: String) -> Response<RespBody> {
    let mut r = Response::new(
        Full::new(Bytes::from(html))
            .map_err(|never| match never {})
            .boxed()
    );

    r.headers_mut()
        .insert("content-type", "text/html; charset=utf-8".parse().unwrap());

    r
}

fn render_org(path: &PathBuf) -> Option<Response<RespBody>> {
    let output = Command::new("pandoc")
        .arg(path)
        .arg("-f")
        .arg("org")
        .arg("-t")
        .arg("html")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(html_response(String::from_utf8_lossy(&output.stdout).to_string()))
}

fn render_markdown(path: &PathBuf) -> Option<Response<RespBody>> {
    let content = fs::read_to_string(path).ok()?;

    let parser = Parser::new(&content);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);

    let full = format!(
        "<html><head><meta charset=\"utf-8\"></head><body>{}</body></html>",
        html_output
    );

    Some(html_response(full))
}


fn render_if_needed(path: &PathBuf) -> Option<Response<RespBody>> {

    eprint!("Checking if rendering needed for: {}\n", path.display());

    match path.extension().and_then(OsStr::to_str) {
        Some("md") => render_markdown(path),
        Some("org") => render_org(path),
        // Some("pdf") => render_pdf(path),
        _ => None,
    }
}
