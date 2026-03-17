


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
use urlencoding::decode;
// use env_logger;
use tracing_subscriber;
use tracing::{info, warn, error, debug};

use crate::types::RespBody;
use crate::proxy::websocket::is_websocket_request;

// // mod config;
// use config::{file, merge, final::FinalConfig};
// use clap::Parser;

mod config;

// use config::args::Args;
// use config::runtime::FinalConfig;

enum HandlerResponse {
    Static(Response<RespBody>),
    Proxy(Response<RespBody>),
}

// #[derive(Parser)]
// #[command(name = "usrhttpd")]
// #[command(about = "Small Rust .htaccess web server")]
// struct Args {
//     // #[arg(short = 'r', long, default_value = "./public")]
//     #[arg(default_value = "./public")]
//     root: String,

//     #[arg(short = 'H', long, default_value = "127.0.0.1")]
//     host: String,

//     #[arg(short = 'p', long, default_value_t = 8080)]
//     port: u16,

//     #[arg(long)]
//     tls_cert: Option<String>,

//     #[arg(long)]
//     tls_key: Option<String>,

//     #[arg(long)]
//     config: Option<String>,

//     // #[arg(long)]
//     // websocket: bool,
// }


// #[derive(Parser, Debug)]
// #[command(name = "usrhttpd")]
// #[command(about = "Small Rust .htaccess web server")]
// struct Args {
//     #[arg(short = 'r', long)]   // , default_value = "./public"
//     root: Option<String>,

//     #[arg(short = 'H', long)]   // default_value = "127.0.0.1"
//     host: Option<String>,

//     #[arg(short = 'p', long)]   // default_value_t = 8080
//     port: Option<u16>,

//     #[arg(long)]
//     tls_cert: Option<String>,

//     #[arg(long)]
//     tls_key: Option<String>,

//     #[arg(long)]
//     config: Option<String>,
// }

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger::init();
    tracing_subscriber::fmt::init();
    // let args = Args::parse();
    let args = config::parse();
    let file_cfg = config::load();
    let merged = config::merge(args, file_cfg);
    let config = config::finalize(merged);

    info!("Starting server with root: {}, host: {}, port: {}, TLS: {}", config.root, config.host, config.port, if config.tls_cert.is_some() && config.tls_key.is_some() { "enabled" } else { "disabled" });

    let root = std::fs::canonicalize(&config.root)?;

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    let tls_acceptor = if let (Some(cert), Some(key)) = (config.tls_cert, config.tls_key) {
        Some(load_tls(cert, key)?)
    } else {
        None
    };


    info!("Server started with root: {}, TLS: {}", root.display(), if tls_acceptor.is_some() { "enabled" } else { "disabled" });

    let cache = Arc::new(cache::HtCache::new());
    let log = Arc::new(access_log::AccessLogger::new("access.log")?);

    info!("Entering main loop");


    loop {
        let (stream, remote) = listener.accept().await?;

        let root = root.clone();
        let cache = cache.clone();
        let log = log.clone();
        let tls_acceptor = tls_acceptor.clone();
        // let websocket_enabled = config.websocket;

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
                    Err(e) => info!("TLS error: {}", e),
                }
            } else {
                let io = TokioIo::new(stream);
                serve_connection_with_options(io, service).await;
            }
        });
    }
}


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
        info!("Connection error: {}", e);
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

    let raw_path = req.uri().path();

    let mut path = decode(raw_path)
        .expect("UTF-8 decoding failed")
        .to_string();


    // // Bad design, implement proper routing instead of hardcoding this hack
    // // by implementing RewriteRule in htaccess resolver
    // if path.ends_with("/jupyter/") {
    //     return Ok(Response::builder()
    //               .status(StatusCode::FOUND)
    //               .header("Location", format!("{}tree", path))
    //               .body(RespBody::default())
    //               .unwrap());
    // }

    // Resolve .htaccess rules
    let rules = htaccess::resolver::resolve(&root, &path, &cache).await;

    // for (pattern, target) in &rules.rewrite_rules {
    //     if pattern == "^$" && rewritten_path == "/" {
    //         rewritten_path = format!("/{}", target);
    //         break;
    //     }
    // }
    for (re, target) in &rules.rewrite_rules {
        if re.is_match(&path) {
            path = re.replace(&path, target.as_str()).to_string();
            break;
        }
    }

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




    let handler = if let Some((prefix, template)) = proxy::match_proxy(&rules, &path) {

        // --- WebSocket detection ---
        if is_websocket_request(&req) {
            let resp = proxy::websocket::handle(req, &prefix, &template).await?;
            return Ok(resp);
        }

        let resp = proxy::reverse::forward_request(req, &prefix, &template, remote).await?;
        HandlerResponse::Proxy(resp)
    } else {
        let resp = static_handler::serve(&req, &root, &path, &rules).await;
        HandlerResponse::Static(resp)
    };

    let response = match handler {
        HandlerResponse::Static(resp) => {

            // Don't gzip already compressed media like video
            let is_video = resp
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.starts_with("video/"))
                .unwrap_or(false);


            let ct = resp
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let skip_gzip =
                ct.starts_with("video/")
                || ct.starts_with("audio/")
                || ct.starts_with("image/")
                || ct.contains("zip");


            if is_video || skip_gzip {
                return Ok(resp);
            }

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
        HandlerResponse::Proxy(resp) => {
            info!("Proxy response with status {}", resp.status());
            resp
        },
    };

    info!(path = %path, status = %response.status(), "Request handled");
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



