

use hyper::{Response, StatusCode};
use bytes::Bytes;
use mime_guess::from_path;
use std::{path::PathBuf, fs};
use http_body_util::{Full, BodyExt};
use crate::types::RespBody;


// pub type RespBody = BoxBody<Bytes, hyper::Error>;

// pub type RespBody = Full<Bytes>;

pub fn serve(root: &PathBuf, path: &str) -> Response<RespBody> {
    let p = root.join(path.trim_start_matches('/'));
    let p = match fs::canonicalize(&p) {
        Ok(v) if v.starts_with(root) => v,
        _ => return resp(StatusCode::FORBIDDEN, "Forbidden"),
    };

    match fs::read(&p) {
        Ok(bytes) => {
            let mime = from_path(&p).first_or_octet_stream();
            // let mut r = Response::new(Full::new(Bytes::from(bytes)));

            let mut r = Response::new(
                // Full::new(Bytes::from(bytes)).boxed()
                Full::new(Bytes::from(bytes))
                    .map_err(|never| match never {})
                    .boxed()
            );

            r.headers_mut().insert("content-type", mime.to_string().parse().unwrap());
            r
        }
        Err(_) => resp(StatusCode::NOT_FOUND, "Not Found"),
    }
}

fn resp(code: StatusCode, body: &str) -> Response<RespBody> {
    Response::builder()
        .status(code)
        // .body(Full::new(Bytes::from(body.to_string())))
        .body(
            Full::new(Bytes::from(body.to_string())).map_err(|never| match never {}).boxed()
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

