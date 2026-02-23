


mod access_log;
mod cache;
mod static_handler;
mod gzip;
mod htaccess;
mod proxy;
mod types;

use anyhow::Result;
use clap::Parser;
use hyper::{Request, Response, body::Incoming};
use hyper_util::{
    rt::TokioIo,
    // rt::{TokioExecutor, TokioIo},
    // server::conn::auto::Builder,

};
use hyper::server::conn::http1;
// use http_body_util::combinators::BoxBody;
// use bytes::Bytes;
use tokio::{net::TcpListener};
use tokio_rustls::TlsAcceptor;
use std::{sync::Arc, net::SocketAddr, path::PathBuf};
use rustls::{ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;

use hyper::service::service_fn;

use crate::types::RespBody;
use crate::proxy::websocket::is_websocket_request;

enum HandlerResponse {
    Static(Response<RespBody>),
    Proxy(Response<RespBody>),
}

#[derive(Parser)]
struct Args {
    #[arg(short = 'r', long, default_value = "./public")]
    root: String,

    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    #[arg(short = 'p', long, default_value_t = 8080)]
    port: u16,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    // #[arg(long)]
    // websocket: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let root = std::fs::canonicalize(&args.root)?;
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    let tls_acceptor = if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
        Some(load_tls(cert, key)?)
    } else {
        None
    };

    let cache = Arc::new(cache::HtCache::new());
    let log = Arc::new(access_log::AccessLogger::new("access.log")?);

    loop {
        let (stream, remote) = listener.accept().await?;

        let root = root.clone();
        let cache = cache.clone();
        let log = log.clone();
        let tls_acceptor = tls_acceptor.clone();
        // let websocket_enabled = args.websocket;

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let root = root.clone();
                let cache = cache.clone();
                let log = log.clone();

                async move {
                    handle_request(req, root, remote, cache, log).await
                }
            });

            if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        serve_connection_with_options(io, service).await;
                    }
                    Err(e) => eprintln!("TLS error: {}", e),
                }
            } else {
                let io = TokioIo::new(stream);
                serve_connection_with_options(io, service).await;
            }
        });
    }
}




// async fn serve_connection_with_options<I, S>(
//     io: I,
//     service: S,
//     enable_ws: bool,
// )
// where
//     I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
//     S: hyper::service::Service<Request<Incoming>, Response = Response<RespBody>, Error = hyper::Error>
//     + Send
//     + 'static,
//     S::Future: Send,
// {
//     let builder = Builder::new(TokioExecutor::new()).http1();

//     let conn = builder.serve_connection(io, service);

//     let conn = if enable_ws {
//         conn.with_upgrades()
//     } else {
//         conn
//     };

//     if let Err(e) = conn.await {
//         eprintln!("Connection error: {}", e);
//     }
// }



// async fn serve_connection_with_options<I, S>(
//     io: I,
//     service: S,
//     enable_ws: bool,
// )
// where
//     I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
//     S: hyper::service::Service<
//         Request<Incoming>,
//     Response = Response<RespBody>,
//     Error = hyper::Error,
//     > + Send + 'static,
//     S::Future: Send,
// {
//     let mut builder = Builder::new(TokioExecutor::new()).http1();

//     if enable_ws {
//         builder = builder.with_upgrades();
//     }

//     if let Err(e) = builder.serve_connection(io, service).await {
//         eprintln!("Connection error: {}", e);
//     }
// }


// async fn serve_connection_with_options<I, S>(
//     io: I,
//     service: S,
//     enable_ws: bool,
// )
// where
//     I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
//     S: hyper::service::Service<
//         hyper::Request<hyper::body::Incoming>,
//     Response = hyper::Response<crate::types::RespBody>,
//     Error = hyper::Error,
//     > + Send + 'static,
//     S::Future: Send,
// {
//     let builder = Builder::new(TokioExecutor::new()).http1();

//     let conn = builder.serve_connection(io, service);

//     let conn = if enable_ws {
//         conn.with_upgrades()
//     } else {
//         conn
//     };

//     if let Err(e) = conn.await {
//         eprintln!("Connection error: {}", e);
//     }
// }


// async fn serve_connection_with_options<I, S>(
//     io: I,
//     service: S,
//     enable_ws: bool,
// )
// where
//     I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
//     S: hyper::service::Service<
//         hyper::Request<hyper::body::Incoming>,
//     Response = hyper::Response<crate::types::RespBody>,
//     Error = hyper::Error,
//     > + Send + 'static,
//     S::Future: Send,
// {
//     let mut builder = http1::Builder::new();

//     if enable_ws {
//         builder = builder.keep_alive(true);
//     }

//     let conn = builder.serve_connection(io, service);

//     let conn = if enable_ws {
//         conn.with_upgrades()
//     } else {
//         conn
//     };

//     if let Err(e) = conn.await {
//         eprintln!("Connection error: {}", e);
//     }
// }


// use hyper::server::conn::http1;

async fn serve_connection_with_options<I, S>(
    io: I,
    service: S,
)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::Service<
        hyper::Request<hyper::body::Incoming>,
    Response = hyper::Response<crate::types::RespBody>,
    Error = hyper::Error,
    > + Send + 'static,
    S::Future: Send,
{
    let mut builder = http1::Builder::new();

    builder.keep_alive(true);

    if let Err(e) = builder
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        eprintln!("Connection error: {}", e);
    }
}


async fn handle_request(
    req: Request<Incoming>,
    root: PathBuf,
    remote: SocketAddr,
    cache: Arc<cache::HtCache>,
    log: Arc<access_log::AccessLogger>,
) -> Result<Response<RespBody>, hyper::Error> {

    log.log(&req, remote);

    let path = req.uri().path().to_string();

    // Resolve .htaccess rules
    let rules = htaccess::resolver::resolve(&root, &path, &cache).await;

    // IP check
    if !htaccess::ip::check(&rules, Some(remote.ip())) {
        return Ok(static_handler::forbidden());
    }

    // Auth check
    let auth_header = req.headers().get("authorization")
        .and_then(|v| v.to_str().ok());

    if !htaccess::auth::check(&rules, auth_header) {
        return Ok(static_handler::auth_required());
    }


    let accept_encoding = req
        .headers()
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let handler = if let Some(target) = proxy::match_proxy(&rules, &path) {

        // --- WebSocket detection ---
        if is_websocket_request(&req) {
            let resp = proxy::websocket::handle(req, target).await?;
            return Ok(resp);
        }

        // let resp = proxy::reverse::forward_request(req, &target).await?;
        let resp = proxy::reverse::forward_request(req, &target).await?;
        HandlerResponse::Proxy(resp)
    } else {
        let resp = static_handler::serve(&root, &path);
        HandlerResponse::Static(resp)
    };

    let response = match handler {
        HandlerResponse::Static(resp) => {
            if let Some(enc) = accept_encoding {
                if enc.contains("gzip") {
                    gzip::compress(resp).await
                } else {
                    resp
                }
            } else {
                resp
            }
        }
        HandlerResponse::Proxy(resp) => resp,
    };

    Ok(response)
}

fn load_tls(cert_path: String, key_path: String) -> Result<TlsAcceptor> {

    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let key = pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("No key found"))??;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key.into())?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}



