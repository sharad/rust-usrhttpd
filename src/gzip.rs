use flate2::{write::GzEncoder, Compression};
use std::io::Write;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response};


use hyper::Response;
use http_body_util::{Full};
use bytes::Bytes;
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

use proxy::reverse::RespBody;



pub fn compress(resp: Response<RespBody>) -> Response<RespBody> {
    let (parts, body) = resp.into_parts();

    // Only compress if body is small/static (Full)
    let bytes = hyper::body::to_bytes(body).now_or_never();

    if let Some(Ok(data)) = bytes {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut new_resp = Response::from_parts(
            parts,
            Full::new(Bytes::from(compressed)).boxed(),
        );

        new_resp.headers_mut().insert(
            "Content-Encoding",
            "gzip".parse().unwrap(),
        );

        new_resp
    } else {
        // If streaming or upgrade, don't touch
        Response::from_parts(parts, body)
    }
}

// pub fn compress(body: Vec<u8>) -> Response<Full<Bytes>> {
//     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
//     encoder.write_all(&body).unwrap();
//     let compressed = encoder.finish().unwrap();

//     let mut resp = Response::new(Full::new(Bytes::from(compressed)));
//     resp.headers_mut().insert("Content-Encoding", "gzip".parse().unwrap());
//     resp
// }

