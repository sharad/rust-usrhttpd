use hyper::{Request, Response};
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use http_body_util::BodyExt;
use tracing::{info, warn, error, debug};

use crate::types::RespBody;

pub async fn forward_request(
    mut req: Request<Incoming>,
    prefix: &str,
    template: &str,
) -> Result<Response<RespBody>, hyper::Error> {

    // // Rewrite URI to backend target
    // *req.uri_mut() = target.parse().unwrap();



    let uri = req.uri().clone();
    let path = uri.path();

    let remainder = path.strip_prefix(prefix).unwrap_or("");

    let mut target = template.replace("%s", remainder);

    // if template does not contain query but request has query
    if !target.contains('?') {
        if let Some(q) = uri.query() {
            target.push('?');
            target.push_str(q);
        }
    }

    *req.uri_mut() = target.parse().unwrap();


    let connector = HttpConnector::new();
    let client: Client<_, Incoming> =
        Client::builder(TokioExecutor::new()).build(connector);

    let resp = match client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            info!("Proxy error: {}", e);

            return Ok(Response::builder()
                      .status(502)
                      .body(RespBody::default())
                      .unwrap());
        }
    };

    // Convert body to BoxBody
    Ok(resp.map(|b| b.boxed()))
    // Ok(resp.map(|b| b.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)).boxed()))
}


