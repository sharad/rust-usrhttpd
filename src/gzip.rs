use hyper::Response;
use http_body_util::{Full, BodyExt};
use bytes::Bytes;
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

use crate::types::RespBody;

pub async fn compress(resp: Response<RespBody>) -> Response<RespBody> {
    let (parts, body) = resp.into_parts();

    let collected = body.collect().await;
    let data = match collected {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            // If we fail to collect, just return empty body safely
            return Response::from_parts(
                parts,
                Full::new(Bytes::new()).map_err(|never| match never {}).boxed(),
            );
        }
    };

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut new_resp = Response::from_parts(
        parts,
        Full::new(Bytes::from(compressed)).map_err(|never| match never {}).boxed(),
    );

    new_resp.headers_mut().insert(
        "Content-Encoding",
        "gzip".parse().unwrap(),
    );

    new_resp
}

