


mod access_log;
mod cache;
mod static_handler;
mod gzip;
mod htaccess;
mod proxy;

use anyhow::Result;
use clap::Parser;
use hyper::{Request, Response, body::Incoming};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use http_body_util::combinators::BoxBody;
use bytes::Bytes;
use tokio::{net::TcpListener};
use tokio_rustls::TlsAcceptor;
use std::{sync::Arc, net::SocketAddr, path::PathBuf};
use rustls::{ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;

use hyper::service::service_fn;

use proxy::reverse::RespBody;


enum HandlerResponse {
    Static(Response<RespBody>),
    Proxy(Response<RespBody>),
}

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "./public")]
    root: String,

    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,

    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,
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
                        if let Err(e) =
                            Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await
                        {
                            eprintln!("Connection error: {}", e);
                        }
                    }
                    Err(e) => eprintln!("TLS error: {}", e),
                }
            } else {
                let io = TokioIo::new(stream);
                if let Err(e) =
                    Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                {
                    eprintln!("Connection error: {}", e);
                }
            }
        });
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

    // Determine handler type
    let handler = if let Some(target) = proxy::match_proxy(&rules, &path) {
        let resp = proxy::reverse::forward_request(req, &target).await?;
        HandlerResponse::Proxy(resp)
    } else {
        let resp = static_handler::serve(&root, &path);
        HandlerResponse::Static(resp)
    };

    let response = match handler {
        HandlerResponse::Static(resp) => {
            if let Some(enc) = req.headers().get("accept-encoding") {
                if enc.to_str().unwrap_or("").contains("gzip") {
                    gzip::compress(resp)
                } else {
                    resp
                }
            } else {
                resp
            }
        }
        HandlerResponse::Proxy(resp) => {
            // NEVER gzip proxy responses
            resp
        }
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



