use hyper::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use http_body_util::{BodyExt, Full};
use bytes::Bytes;

use crate::types::RespBody;

pub async fn forward_request(
    mut req: Request<Incoming>,
    target: &str,
) -> Response<RespBody> {

    let connector = HttpConnector::new();
    let client: Client<_, Incoming> =
        Client::builder(TokioExecutor::new()).build(connector);

    // Parse URI safely
    let uri = match target.parse() {
        Ok(u) => u,
        Err(_) => {
            return simple_response(StatusCode::BAD_GATEWAY, "Invalid proxy URI");
        }
    };

    *req.uri_mut() = uri;

    let resp = match client.request(req).await {
        Ok(r) => r,
        Err(_) => {
            return simple_response(StatusCode::BAD_GATEWAY, "Upstream unavailable");
        }
    };

    resp.map(|b| b.boxed())
}

fn simple_response(code: StatusCode, msg: &str) -> Response<RespBody> {
    Response::builder()
        .status(code)
        .body(
            Full::new(Bytes::from(msg.to_string()))
                .map_err(|never| match never {})
                .boxed()
        )
        .unwrap()
}

