use hyper::{Request, Response};
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use http_body_util::BodyExt;

use crate::types::RespBody;

pub async fn forward_request(
    mut req: Request<Incoming>,
    target: &str,
) -> Result<Response<RespBody>, hyper::Error> {

    // Rewrite URI to backend target
    *req.uri_mut() = target.parse().unwrap();

    let connector = HttpConnector::new();
    let client: Client<_, Incoming> =
        Client::builder(TokioExecutor::new()).build(connector);

    let resp = match client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Proxy error: {}", e);

            return Ok(Response::builder()
                      .status(502)
                      .body(RespBody::default())
                      .unwrap());
        }
    };

    // Convert body to BoxBody
    Ok(resp.map(|b| b.boxed()))
}


