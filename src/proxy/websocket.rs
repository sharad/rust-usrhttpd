use hyper::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::upgrade;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use http_body_util::BodyExt;
use tokio::io::copy_bidirectional;

use crate::types::RespBody;

pub fn is_websocket_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

pub async fn handle(
    mut req: Request<Incoming>,
    target: String,
) -> Result<Response<RespBody>, hyper::Error> {

    // Capture client upgrade
    let on_client_upgrade = upgrade::on(&mut req);

    // Rewrite URI to backend target
    *req.uri_mut() = target.parse().unwrap();

    let connector = HttpConnector::new();
    let client: Client<_, Incoming> =
        Client::builder(TokioExecutor::new()).build(connector);

    // Send request to backend
    let mut backend_resp = match client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("WebSocket backend error: {}", e);

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
    Ok(backend_resp.map(|b| b.boxed()))
}


