
use hyper::{Request, Response, StatusCode};
use hyper::body::Incoming;
use bytes::Bytes;
use mime_guess;
use std::{path::PathBuf, fs};
// use http_body_util::{Full, BodyExt};
use http_body_util::{StreamBody, BodyExt, Full};
use std::ffi::OsStr;
use std::process::Command;
use pulldown_cmark::{Parser, html};
use urlencoding::encode;

use tokio::fs::File;
use tokio_util::io::ReaderStream;
// use http_body_util::StreamBody;
use http_body::Frame;
// use futures_util::StreamExt;
use futures_util::StreamExt as _;
// use log::{info, warn, error, debug};
use tracing::{info, warn, error, debug};

use crate::types::RespBody;
use crate::htaccess::rules::HtAccess;


#[derive(Debug, Clone, Copy)]
enum RenderMode {
    Auto,   // default behavior
    Raw,    // serve raw file
    Render, // force render (markdown, etc.)
    List,   // force directory listing
    Download,
    Json,
}

fn parse_render_mode(req: &Request<Incoming>) -> RenderMode {
    let query = req.uri().query().unwrap_or("");

    let params: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    match params.get("mode").map(|s| s.as_str()) {
        Some("raw") => RenderMode::Raw,
        Some("render") => RenderMode::Render,
        Some("list") => RenderMode::List,
        Some("download") => RenderMode::Download,
        Some("json") => RenderMode::Json,
        _ => RenderMode::Auto,
    }
}

pub async fn serve(req: &Request<Incoming>,
                   root: &PathBuf,
                   path: &str,
                   rules: &HtAccess,) -> Response<RespBody> {
    let requested = root.join(path.trim_start_matches('/'));

    let mode = parse_render_mode(req);

    // let levels = rules.follow_symlinks.unwrap_or(10);
    // let boundary = root
    //     .ancestors()
    //     .nth(levels)
    //     .unwrap_or(&root)
    //     .to_path_buf();
    // let boundary = match fs::canonicalize(&boundary) {
    //     Ok(b) => b,
    //     Err(e) => {
    //         info!("Root canonicalize failed: {}", e);
    //         return resp(StatusCode::INTERNAL_SERVER_ERROR, "Server misconfiguration")
    //     },
    // };

    let allowed_roots = if rules.allowed_dirs.is_empty() {
        vec![fs::canonicalize(root).unwrap()]
    } else {
        rules.allowed_dirs
            .iter()
            .filter_map(|d| fs::canonicalize(d).ok())
            .collect()
    };

    info!("---- Allowed Roots ----");
    for r in &allowed_roots {
        info!("{}", r.display());
    }
    info!("-----------------------");


    info!("root: {}", root.display());
    // info!("Serving static: boundary={}", boundary.display());

    // info!(client = %remote, path = %path, "Incoming request");

    let p = match fs::canonicalize(&requested) {
        Ok(v) => {
            info!("Serving static: requested={}", requested.display());
            // info!("Resolved path: {:?}", v);
            info!("Resolved path: {}", v.display());

            info!(path = %v.display(), "Serving file");

            if !allowed_roots.iter().any(|r| v.starts_with(r)) {
                return resp(StatusCode::FORBIDDEN, "Forbidden");
            }

            v
        }

        Err(e) => {
            use std::io::ErrorKind;

            info!("Request canonicalize failed: {}", e);

            match e.kind() {
                ErrorKind::NotFound => {
                    return resp(StatusCode::NOT_FOUND, "Not Found");
                }
                ErrorKind::PermissionDenied => {
                    return resp(StatusCode::FORBIDDEN, "Forbidden");
                }
                _ => {
                    return resp(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
                }
            }
        }
    };

    // 🔹 If directory → try index files
    // if p.is_dir() {
    //     if let Some(index) = find_index(&p) {
    //         return serve_file(index).await;
    //     }

    //     // Directory listing control via htaccess
    //     let allow_listing = rules.options_indexes.unwrap_or(true);

    //     if !allow_listing {
    //         return resp(StatusCode::FORBIDDEN, "Directory listing denied");
    //     }

    //     return directory_listing(&p);
    // }

    // if p.is_dir() {

    //     match mode {
    //         RenderMode::Raw => {
    //             return resp(StatusCode::FORBIDDEN, "Cannot raw-read directory");
    //         }

    //         RenderMode::List => {
    //             return directory_listing(&p);
    //         }

    //         _ => {}
    //     }

    //     if let Some(index) = find_index(&p) {
    //         return serve_file(index, mode).await;
    //     }

    //     let allow_listing = rules.options_indexes.unwrap_or(true);

    //     if !allow_listing {
    //         return resp(StatusCode::FORBIDDEN, "Directory listing denied");
    //     }

    //     return directory_listing(&p);
    // }

    if p.is_dir() {
        match mode {
            RenderMode::Raw | RenderMode::Download => {
                return resp(StatusCode::FORBIDDEN, "Cannot download directory");
            }

            RenderMode::List => {
                return directory_listing(&p);
            }

            RenderMode::Json => {
                return directory_listing_json(&p);
            }

            _ => {}
        }

        if let Some(index) = find_index(&p) {
            return serve_file(index, mode).await;
        }

        let allow_listing = rules.options_indexes.unwrap_or(true);

        if !allow_listing {
            return resp(StatusCode::FORBIDDEN, "Directory listing denied");
        }

        return directory_listing(&p);
    }


    // 🔹 Normal file
    serve_file(p, mode).await
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

// async fn serve_file(path: PathBuf, mode: RenderMode) -> Response<RespBody> {

//     if let Some(resp) = render_if_needed(&path) {
//         return resp;
//     }

//     match File::open(&path).await {
//         Ok(file) => {

//             let size = match file.metadata().await {
//                 Ok(m) => m.len(),
//                 Err(_) => 0
//             };

//             let mime = mime_guess::from_path(&path).first_or_octet_stream();

//             let stream = ReaderStream::new(file)
//                 .map(|result| Ok(Frame::data(result.unwrap())));

//             let body = BodyExt::boxed(StreamBody::new(stream));


//             let mut resp = Response::new(body);

//             // set content type
//             resp.headers_mut().insert(
//                 hyper::header::CONTENT_TYPE,
//                 mime.to_string().parse().unwrap()
//             );

//             // // ADD CONTENT LENGTH HERE
//             if size > 0 {
//                 resp.headers_mut().insert(
//                     hyper::header::CONTENT_LENGTH,
//                     size.to_string().parse().unwrap()
//                 );
//             }

//             resp.headers_mut().insert(
//                 hyper::header::ACCEPT_RANGES,
//                 "bytes".parse().unwrap()
//             );

//             resp
//         }

//         Err(e) => {
//             info!("Reading failed: {}", e);
//             resp(StatusCode::NOT_FOUND, "Not Found")
//         }

//     }
// }


// async fn serve_file(path: PathBuf, mode: RenderMode) -> Response<RespBody> {

//     // 🔥 Mode override FIRST
//     match mode {
//         RenderMode::Raw => {
//             return serve_raw_file(path).await;
//         }

//         RenderMode::Render => {
//             if let Some(resp) = render_if_needed(&path) {
//                 return resp;
//             }
//         }

//         RenderMode::Auto => {
//             if let Some(resp) = render_if_needed(&path) {
//                 return resp;
//             }
//         }

//         _ => {}
//     }

//     serve_raw_file(path).await
// }


async fn serve_file(path: PathBuf, mode: RenderMode) -> Response<RespBody> {

    match mode {
        RenderMode::Raw => {
            return serve_raw_file(path, false).await;
        }

        RenderMode::Download => {
            return serve_raw_file(path, true).await;
        }

        RenderMode::Render => {
            if let Some(resp) = render_if_needed(&path) {
                return resp;
            }
        }

        RenderMode::Json => {
            return file_as_json(&path);
        }

        RenderMode::Auto => {
            if let Some(resp) = render_if_needed(&path) {
                return resp;
            }
        }

        _ => {}
    }

    serve_raw_file(path, false).await
}


// async fn serve_raw_file(path: PathBuf) -> Response<RespBody> {
//     match File::open(&path).await {
//         Ok(file) => {
//             let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);

//             let mime = mime_guess::from_path(&path).first_or_octet_stream();

//             let stream = ReaderStream::new(file)
//                 .map(|result| Ok(Frame::data(result.unwrap())));

//             let body = BodyExt::boxed(StreamBody::new(stream));

//             let mut resp = Response::new(body);

//             resp.headers_mut().insert(
//                 hyper::header::CONTENT_TYPE,
//                 mime.to_string().parse().unwrap(),
//             );

//             if size > 0 {
//                 resp.headers_mut().insert(
//                     hyper::header::CONTENT_LENGTH,
//                     size.to_string().parse().unwrap(),
//                 );
//             }

//             resp.headers_mut().insert(
//                 hyper::header::ACCEPT_RANGES,
//                 "bytes".parse().unwrap(),
//             );

//             resp
//         }

//         Err(e) => {
//             info!("Reading failed: {}", e);
//             resp(StatusCode::NOT_FOUND, "Not Found")
//         }
//     }
// }


async fn serve_raw_file(path: PathBuf, download: bool) -> Response<RespBody> {
    match File::open(&path).await {
        Ok(file) => {
            let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);

            let mime = mime_guess::from_path(&path).first_or_octet_stream();

            let stream = ReaderStream::new(file)
                .map(|result| Ok(Frame::data(result.unwrap())));

            let body = BodyExt::boxed(StreamBody::new(stream));

            let mut resp = Response::new(body);

            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                mime.to_string().parse().unwrap(),
            );

            if size > 0 {
                resp.headers_mut().insert(
                    hyper::header::CONTENT_LENGTH,
                    size.to_string().parse().unwrap(),
                );
            }

            resp.headers_mut().insert(
                hyper::header::ACCEPT_RANGES,
                "bytes".parse().unwrap(),
            );

            // 🔥 Download mode
            if download {
                let filename = path.file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("file");

                let value = format!("attachment; filename=\"{}\"", filename);

                resp.headers_mut().insert(
                    hyper::header::CONTENT_DISPOSITION,
                    value.parse().unwrap(),
                );
            }

            resp
        }

        Err(e) => {
            info!("Reading failed: {}", e);
            resp(StatusCode::NOT_FOUND, "Not Found")
        }
    }
}


fn directory_listing_json(path: &PathBuf) -> Response<RespBody> {
    let mut entries = vec![];

    if let Ok(read_dir) = std::fs::read_dir(path) {
        // for entry in read_dir.flatten() {
        //     let meta = entry.metadata().ok();

        //     entries.push(serde_json::json!({
        //         "name": entry.file_name().to_string_lossy(),
        //         "is_dir": meta.map(|m| m.is_dir()).unwrap_or(false),
        //         "size": meta.map(|m| m.len()).unwrap_or(0),
        //     }));
        // }


        for entry in read_dir.flatten() {
            let (is_dir, size) = match entry.metadata() {
                Ok(m) => (m.is_dir(), m.len()),
                Err(_) => (false, 0),
            };

            entries.push(serde_json::json!({
                "name": entry.file_name().to_string_lossy(),
                "is_dir": is_dir,
                "size": size,
            }));
        }

    }



    let body = serde_json::to_string_pretty(&entries).unwrap();

    Response::builder()
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed()
        )
        .unwrap()
}


fn file_as_json(path: &PathBuf) -> Response<RespBody> {
    let content = std::fs::read_to_string(path).unwrap_or_default();

    let body = serde_json::json!({
        "path": path.display().to_string(),
        "content": content
    });

    Response::builder()
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body.to_string()))
                .map_err(|never| match never {})
                .boxed()
        )
        .unwrap()
}

pub fn generate_directory_html(dir: &PathBuf) -> Result<String, std::io::Error> {
    let mut entries = fs::read_dir(dir)?;

    let mut html = String::new();

    let dirname = dir.file_name().and_then(OsStr::to_str).unwrap_or("/");

    html.push_str("<html><head><title>Index of ");
    html.push_str(dirname);
    html.push_str("</title></head><body>");
    html.push_str("<h1>Index of ");
    html.push_str(dirname);
    html.push_str("</h1><hr><ul>");

    html.push_str("<li style=\"white-space: pre\"><a href=\"..\">../</a></li>");

    // ----------------------------
    // Directory entries
    // ----------------------------
    while let Some(Ok(entry)) = entries.next() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name  == "index.html" {
            continue;
        }
        let mut display = name.to_string();
        let mut href = encode(&display).to_string();
        if entry.path().is_dir() {
            href.push('/');
            display.push('/')
        }

        html.push_str("<li style=\"white-space: pre\"><a href=\"");
        html.push_str(&href);
        html.push_str("\">");
        html.push_str(&display);
        html.push_str("</a></li>");
    }

    html.push_str("</ul><hr></body></html>");

    Ok(html)
}


fn directory_listing(dir: &PathBuf) -> Response<RespBody> {


    match generate_directory_html(dir) {
        Ok(html) => {
            let mut r = Response::new(
                Full::new(Bytes::from(html))
                    .map_err(|never| match never {})
                    .boxed()
            );

            r.headers_mut()
                .insert("content-type", "text/html".parse().unwrap());

            r
        }
        Err(_) => resp(StatusCode::FORBIDDEN, "Forbidden"),
    }
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

    info!("Checking if rendering needed for: {}", path.display());

    match path.extension().and_then(OsStr::to_str) {
        Some("md") => render_markdown(path),
        Some("org") => render_org(path),
        // Some("pdf") => render_pdf(path),
        _ => None,
    }
}
