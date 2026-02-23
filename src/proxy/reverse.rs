
use hyper::{Request, Response, body::Incoming};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use http_body_util::combinators::BoxBody;
use bytes::Bytes;
use anyhow::Result;

pub type RespBody = BoxBody<Bytes, hyper::Error>;

pub async fn forward_request(
    mut req: Request<Incoming>,
    target: &str,
) -> Result<Response<RespBody>, hyper::Error> {

    let client: Client<HttpConnector, Incoming> =
        Client::builder(TokioExecutor::new()).build_http();

    let new_uri = format!("{}{}", target, req.uri().path());
    *req.uri_mut() = new_uri.parse().unwrap();

    let resp = client.request(req).await?;

    Ok(resp.map(|b| b.boxed()))
}

