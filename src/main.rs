


mod access_log;
mod cache;
mod static_handler;
mod gzip;
mod htaccess;
mod proxy;
mod types;

use anyhow::Result;
use hyper::{Request, Response, body::Incoming};
use hyper_util::{
    rt::TokioIo,
    // rt::{TokioExecutor, TokioIo},
    // server::conn::auto::Builder,

};
use hyper::server::conn::http1;
// use http_body_util::combinators::BoxBody;
// use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use std::{
    io::BufReader,
    fs::File,
    sync::Arc,
    net::SocketAddr,
    path::PathBuf
};
use rustls::{ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

use hyper::service::service_fn;
use urlencoding::decode;
// use env_logger;
use tracing_subscriber;
use tracing::{info, warn, error, debug};

use crate::types::RespBody;
use crate::proxy::websocket::is_websocket_request;

mod config;

enum HandlerResponse {
    Static(Response<RespBody>),
    Proxy(Response<RespBody>),
}

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger::init();
    let config = config::load_all();



    // tracing_subscriber::fmt::init();
    if !config.inetd.unwrap_or(false) {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            info!("stdin  fd = {}", std::io::stdin().as_raw_fd());
            info!("stdout fd = {}", std::io::stdout().as_raw_fd());
            info!("stderr fd = {}", std::io::stderr().as_raw_fd());
        }
    }


    info!(
        "Starting server with root: {}, host: {}, port: {}, TLS: {}, inetd: {}",
        config.root,
        config.host,
        config.port,
        if config.tls_cert.is_some() && config.tls_key.is_some() {
            "enabled"
        } else {
            "disabled"
        },
        config.inetd.unwrap_or(false),
    );


    let root = std::fs::canonicalize(&config.root)?;

    // let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    // let listener = TcpListener::bind(addr).await?;
    // println!("Listening on {}", addr);

    let tls_acceptor = if let (Some(cert), Some(key)) = (config.tls_cert, config.tls_key) {
        Some(load_tls(cert, key)?)
    } else {
        None
    };


    info!("Server started with root: {}, TLS: {}", root.display(), if tls_acceptor.is_some() { "enabled" } else { "disabled" });

    let cache = Arc::new(cache::HtCache::new());
    let log = Arc::new(access_log::AccessLogger::new(config.alog.as_deref())?);

    info!("Entering main loop");


    tokio::spawn(async {
        loop {
            proxy::cmd::cleanup_expired().await;

            tokio::time::sleep(
                std::time::Duration::from_secs(30)
            ).await;
        }
    });

    if config.inetd.unwrap_or(false) {
        run_inetd(
            root,
            cache,
            log,
            tls_acceptor,
        ).await
    } else {
        run_listener(
            config.host,
            config.port,
            root,
            cache,
            log,
            tls_acceptor,
        ).await
    }

    // loop {
    //     let (stream, remote) = listener.accept().await?;

    //     let root = root.clone();
    //     let cache = cache.clone();
    //     let log = log.clone();
    //     let tls_acceptor = tls_acceptor.clone();
    //     // let websocket_enabled = config.websocket;

    //     tokio::spawn(async move {
    //         let service = service_fn(move |req: Request<Incoming>| {
    //             let root = root.clone();
    //             let cache = cache.clone();
    //             let log = log.clone();

    //             async move {
    //                 handle_request(req, root, remote, cache, log).await
    //             }
    //         });

    //         if let Some(acceptor) = tls_acceptor {
    //             match acceptor.accept(stream).await {
    //                 Ok(tls_stream) => {
    //                     let io = TokioIo::new(tls_stream);
    //                     serve_connection_with_options(io, service).await;
    //                 }
    //                 Err(e) => info!("TLS error: {}", e),
    //             }
    //         } else {
    //             let io = TokioIo::new(stream);
    //             serve_connection_with_options(io, service).await;
    //         }
    //     });
    // }
}


#[cfg(unix)]
async fn run_inetd(
    root: PathBuf,
    cache: Arc<cache::HtCache>,
    log: Arc<access_log::AccessLogger>,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // Shepherd/inetd gives us the connected socket on stdin (fd 0).
    let stdin_fd = std::io::stdin().as_raw_fd();

    // Duplicate fd 0 so that converting it into TcpStream does not
    // take ownership of Shepherd's original stdin descriptor.
    let fd = unsafe { libc::dup(stdin_fd) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let std_stream = unsafe {
        std::net::TcpStream::from_raw_fd(fd)
    };

    std_stream.set_nonblocking(true)?;

    let stream = TcpStream::from_std(std_stream)?;

    let remote = stream
        .peer_addr()
        .unwrap_or_else(|_| {
            "0.0.0.0:0".parse().unwrap()
        });

    info!(
        "inetd connection accepted from {}",
        remote
    );

    handle_stream(
        stream,
        remote,
        root,
        cache,
        log,
        tls_acceptor,
    ).await;

    info!(
        "inetd connection closed: {}",
        remote
    );

    Ok(())
}


async fn run_listener(
    host: String,
    port: u16,
    root: PathBuf,
    cache: Arc<cache::HtCache>,
    log: Arc<access_log::AccessLogger>,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    let listener = TcpListener::bind(addr).await?;

    info!("Listening on {}", addr);



    loop {
        let (stream, remote) = listener.accept().await?;

        info!(
            "Connection accepted from {}",
            remote
        );

        let root = root.clone();
        let cache = cache.clone();
        let log = log.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            handle_stream(
                stream,
                remote,
                root,
                cache,
                log,
                tls_acceptor,
            ).await;
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

// async fn handle_stream<S>(
//     stream: S,
//     remote: SocketAddr,
//     root: PathBuf,
//     cache: Arc<cache::HtCache>,
//     log: Arc<access_log::AccessLogger>,
//     tls_acceptor: Option<TlsAcceptor>,
// )
// where
//     S: tokio::io::AsyncRead
//         + tokio::io::AsyncWrite
//         + Unpin
//         + Send
//         + 'static,
// {
//     let service = service_fn(move |req: Request<Incoming>| {
//         let root = root.clone();
//         let cache = cache.clone();
//         let log = log.clone();

//         async move {
//             handle_request(req, root, remote, cache, log).await
//         }
//     });

//     if let Some(acceptor) = tls_acceptor {
//         match acceptor.accept(stream).await {
//             Ok(tls_stream) => {
//                 let io = TokioIo::new(tls_stream);
//                 serve_connection_with_options(io, service).await;
//             }

//             Err(e) => {
//                 info!("TLS error: {}", e);
//             }
//         }
//     } else {
//         let io = TokioIo::new(stream);
//         serve_connection_with_options(io, service).await;
//     }
// }


async fn handle_stream<I>(
    stream: I,
    remote: SocketAddr,
    root: PathBuf,
    cache: Arc<cache::HtCache>,
    log: Arc<access_log::AccessLogger>,
    tls_acceptor: Option<TlsAcceptor>,
)
where
    I: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + Unpin
        + Send
        + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let root = root.clone();
        let cache = cache.clone();
        let log = log.clone();

        async move {
            handle_request(
                req,
                root,
                remote,
                cache,
                log,
            ).await
        }
    });

    if let Some(acceptor) = tls_acceptor {
        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                let io = TokioIo::new(tls_stream);

                serve_connection_with_options(
                    io,
                    service,
                ).await;
            }

            Err(e) => {
                info!(
                    "TLS error from {}: {}",
                    remote,
                    e
                );
            }
        }
    } else {
        let io = TokioIo::new(stream);

        serve_connection_with_options(
            io,
            service,
        ).await;
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


    if let Some(cmd) =
        proxy::match_proxy_cmd(&rules, &path)
    {
        proxy::cmd::ensure_running(
            &cmd.prefix,
            &cmd.target,
            cmd.ttl_secs,
            &cmd.command,
            &root,
        ).await;

        let resp =
            proxy::reverse::forward_request(
                req,
                &cmd.prefix,
                &cmd.target,
                remote,
            ).await?;

        return Ok(resp);
    }


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



