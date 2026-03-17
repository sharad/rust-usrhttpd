

use hyper::{Request, Response};
use hyper::body::Incoming;
// use hyper_util::client::legacy::{Client, connect::HttpConnector};
// use hyper_util::rt::TokioExecutor;
use hyper::header::HOST;
use hyper::http::Uri;
use hyper::header::{HeaderName, HeaderValue};
use http_body_util::BodyExt;
use tracing::{info, warn, error, debug};

use crate::types::RespBody;
use crate::proxy::http_client::HTTP_CLIENT;



// $ cat .htaccess
// ProxyPass /Documents/Collection/Compositions/Drafts/misc/jupyter/ http://localhost:8888/Documents/Collection/Compositions/Drafts/misc/jupyter/%s?token=mytoken
// ProxyPass /Documents/Compositions/Drafts/misc/jupyter/ http://localhost:8888/Documents/Compositions/Drafts/misc/jupyter/%s?token=mytoken

// $ jupyter server \                                                                                                                                                                                              1994s
//     --port 8888 \
//     --ServerApp.base_url=/Documents/Compositions/Drafts/misc/jupyter/ \
//     --ServerApp.token=mytoken



pub async fn forward_request(
    mut req: Request<Incoming>,
    prefix: &str,
    template: &str,
    remote: std::net::SocketAddr,
) -> Result<Response<RespBody>, hyper::Error> {
    let uri = req.uri().clone();
    let path = uri.path();

    let remainder = path.strip_prefix(prefix).unwrap_or("");

    info!(prefix = %prefix, path = %path, remainder = %remainder, template = %template, "forwarding request");

    let mut target = template.replace("%s", remainder);

    // if template does not contain query but request has query
    if !target.contains('?') {
        if let Some(q) = uri.query() {
            target.push('?');
            target.push_str(q);
        }
    }

    info!(prefix = %prefix, target = %target, "proxying request");

    let backend_uri: Uri = target.parse().unwrap();
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = backend_uri.scheme().cloned();
    parts.authority = backend_uri.authority().cloned();
    parts.path_and_query = backend_uri.path_and_query().cloned();
    *req.uri_mut() = Uri::from_parts(parts).unwrap();

    // extract host header first
    let original_host = req
        .headers()
        .get(HOST)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("localhost"));

    let backend_uri: Uri = target.parse().unwrap();

    if let Some(authority) = backend_uri.authority() {
        req.headers_mut().insert(
            HOST,
            HeaderValue::from_str(authority.as_str()).unwrap(),
        );
    }

    let client_ip = remote.ip().to_string();

    req.headers_mut().insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client_ip).unwrap(),
    );

    req.headers_mut().insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("http"),
    );

    req.headers_mut().insert(
        HeaderName::from_static("x-forwarded-host"),
        original_host,
    );




    let resp: Response<Incoming>  = match HTTP_CLIENT.request(req).await {
        Ok(r) => r,
        Err(e) => {
            info!("Proxy error: {}", e);

            return Ok(Response::builder()
                      .status(502)
                      .body(RespBody::default())
                      .unwrap());
        }
    };


    let mut resp = resp;

    if let Some(loc) = resp.headers().get(hyper::header::LOCATION).cloned() {
        if let Ok(loc_str) = loc.to_str() {

            if loc_str.starts_with("http://localhost:8888") {
                let new_loc = loc_str.replace("http://localhost:8888", prefix);

                resp.headers_mut().insert(
                    hyper::header::LOCATION,
                    HeaderValue::from_str(&new_loc).unwrap(),
                );
            }

            if loc_str.starts_with("/tree") {
                let new_loc = format!("{}{}", prefix, loc_str.trim_start_matches('/'));

                resp.headers_mut().insert(
                    hyper::header::LOCATION,
                    HeaderValue::from_str(&new_loc).unwrap(),
                );
            }


            info!("Backend redirect: {}", loc_str);
        }
    }

    // Convert body to BoxBody
    Ok(resp.map(|b: Incoming| b.boxed()))
}


