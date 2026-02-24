
use hyper::{Response, StatusCode};
use bytes::Bytes;
use mime_guess::from_path;
use std::{path::PathBuf, fs};
use http_body_util::{Full, BodyExt};
use crate::types::RespBody;
use crate::htaccess::rules::HtAccess;

pub fn serve(root: &PathBuf, path: &str, rules: &HtAccess,) -> Response<RespBody> {
    let requested = root.join(path.trim_start_matches('/'));

    let p = match fs::canonicalize(&requested) {
        Ok(v) if v.starts_with(root) => v,
        _ => return resp(StatusCode::FORBIDDEN, "Forbidden"),
    };

    // if p.is_dir() {
    //     if let Some(index) = find_index(&p) {
    //         return serve_file(index);
    //     }

    //     return directory_listing(&p, path);
    // }


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
    let html = dir.join("index.html");
    if html.exists() {
        return Some(html);
    }

    let htm = dir.join("index.htm");
    if htm.exists() {
        return Some(htm);
    }

    None
}

fn serve_file(path: PathBuf) -> Response<RespBody> {
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



