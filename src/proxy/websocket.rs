

use hyper::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::upgrade;
use hyper::http::Uri;
use hyper_util::rt::TokioIo;
// use hyper_util::client::legacy::{Client, connect::HttpConnector};
// use hyper_util::rt::{TokioExecutor, TokioIo};
use http_body_util::BodyExt;
use tokio::io::copy_bidirectional;

use tracing::{info, warn, error, debug};

use crate::types::RespBody;
use crate::proxy::http_client::HTTP_CLIENT;


pub fn is_websocket_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

pub async fn handle(
    mut req: Request<Incoming>,
    prefix: &str,
    template: &str,
) -> Result<Response<RespBody>, hyper::Error> {

    // Capture client upgrade
    let on_client_upgrade = upgrade::on(&mut req);






    let uri = req.uri().clone();
    let path = uri.path();

    let remainder = path.strip_prefix(prefix).unwrap_or("");

    let mut target = template.replace("%s", remainder);

    if !target.contains('?') {
        if let Some(q) = uri.query() {
            target.push('?');
            target.push_str(q);
        }
    }
    let backend_uri: Uri = target.parse().unwrap();

    let mut parts = req.uri().clone().into_parts();
    parts.scheme = backend_uri.scheme().cloned();
    parts.authority = backend_uri.authority().cloned();
    parts.path_and_query = backend_uri.path_and_query().cloned();

    *req.uri_mut() = Uri::from_parts(parts).unwrap();

    // Send request to backend
    let mut backend_resp: Response<Incoming>  = match HTTP_CLIENT.request(req).await {
        Ok(r) => r,
        Err(e) => {
            info!("WebSocket backend error: {}", e);

            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(RespBody::default())
                .unwrap());
        }
    };

    // Must be 101
    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(backend_resp.map(|b| b.boxed()));
    }

    // Capture backend upgrade
    let on_backend_upgrade = upgrade::on(&mut backend_resp);

    // Spawn tunnel task
    tokio::spawn(async move {
        if let (Ok(client_upgraded), Ok(backend_upgraded)) =
            (on_client_upgrade.await, on_backend_upgrade.await)
        {
            let mut client_io = TokioIo::new(client_upgraded);
            let mut backend_io = TokioIo::new(backend_upgraded);

            let _ = copy_bidirectional(&mut client_io, &mut backend_io).await;
        }
    });

    // Return backend 101 to client
    Ok(backend_resp.map(|b: Incoming| b.boxed()))
}


