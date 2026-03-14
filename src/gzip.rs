use hyper::Response;
use http_body_util::{Full, BodyExt};
use bytes::Bytes;
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

use crate::types::RespBody;

pub async fn compress(resp: Response<RespBody>) -> Response<RespBody> {

    let (mut parts, body) = resp.into_parts();

    let collected = body.collect().await;
    let data = match collected {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::from_parts(
                parts,
                Full::new(Bytes::new()).map_err(|never| match never {}).boxed(),
            );
        }
    };

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    // remove old content-length
    parts.headers.remove(hyper::header::CONTENT_LENGTH);

    // add gzip encoding
    parts.headers.insert(
        hyper::header::CONTENT_ENCODING,
        "gzip".parse().unwrap(),
    );

    // set correct length
    parts.headers.insert(
        hyper::header::CONTENT_LENGTH,
        compressed.len().to_string().parse().unwrap(),
    );

    Response::from_parts(
        parts,
        Full::new(Bytes::from(compressed))
            .map_err(|never| match never {})
            .boxed(),
    )
}

