use std::{
    convert::Infallible,
    fs::File,
    io::{BufReader},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use chrono::Local;
use clap::Parser;
use hyper::{
    body::Incoming,
    header::{AUTHORIZATION, CONTENT_TYPE},
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_util::{
    rt::TokioExecutor,
    server::conn::auto::Builder,
};
use http_body_util::Full;
use mime_guess::from_path;
use sha1::{Digest, Sha1};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};

use hyper_util::rt::TokioIo;

type RespBody = Full<Bytes>;

#[derive(Parser)]
struct Args {
    root: String,

    #[arg(short='H', long, default_value="127.0.0.1")]
    host: IpAddr,

    #[arg(short='p', long, default_value_t=8080)]
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
    let addr = SocketAddr::new(args.host, args.port);

    println!("Serving {}", root.display());
    println!("Listening on http{}://{}",
        if args.tls_cert.is_some() { "s" } else { "" },
        addr);

    let listener = TcpListener::bind(addr).await?;

    let tls_acceptor = if let (Some(cert), Some(key)) =
        (args.tls_cert.clone(), args.tls_key.clone()) {
        Some(load_tls(cert, key)?)
    } else {
        None
    };

    loop {
        let (stream, remote) = listener.accept().await?;
        let root = root.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req|
                handle(req, root.clone(), remote.ip())
            );

            // if let Some(acceptor) = tls_acceptor {
            //     let stream = acceptor.accept(stream).await.unwrap();
            //     Builder::new(TokioExecutor::new())
            //         .serve_connection(stream, service)
            //         .await
            //         .unwrap();
            // } else {
            //     Builder::new(TokioExecutor::new())
            //         .serve_connection(stream, service)
            //         .await
            //         .unwrap();
            // }



            if let Some(acceptor) = tls_acceptor {
                let tls_stream = acceptor.accept(stream).await.unwrap();
                let io = TokioIo::new(tls_stream);

                Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                    .unwrap();
            } else {
                let io = TokioIo::new(stream);

                Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                    .unwrap();
            }


        });
    }
}

async fn handle(
    req: Request<Incoming>,
    root: PathBuf,
    remote_ip: IpAddr,
) -> Result<Response<RespBody>, Infallible> {

    log_request(&req, remote_ip);

    let path = req.uri().path().trim_start_matches('/');
    let mut fs_path = root.join(path);

    if fs_path.is_dir() {
        fs_path = fs_path.join("index.html");
    }

    let fs_path = match std::fs::canonicalize(&fs_path) {
        Ok(p) => p,
        Err(_) => return Ok(resp(StatusCode::NOT_FOUND, "Not Found")),
    };

    if !fs_path.starts_with(&root) {
        return Ok(resp(StatusCode::FORBIDDEN, "Forbidden"));
    }

    if let Some(userfile) = htpasswd_path(&root) {
        if !check_auth(&req, &userfile) {
            return Ok(auth_challenge());
        }
    }

    match tokio::fs::read(&fs_path).await {
        Ok(bytes) => {
            let mime = from_path(&fs_path).first_or_octet_stream();
            let mut r = Response::new(Full::new(Bytes::from(bytes)));
            *r.status_mut() = StatusCode::OK;
            r.headers_mut().insert(
                CONTENT_TYPE,
                mime.to_string().parse().unwrap(),
            );
            Ok(r)
        }
        Err(_) => Ok(resp(StatusCode::NOT_FOUND, "Not Found")),
    }
}

fn htpasswd_path(root: &Path) -> Option<PathBuf> {
    let p = root.join(".htpasswd");
    if p.exists() { Some(p) } else { None }
}

fn check_auth(req: &Request<Incoming>, userfile: &Path) -> bool {
    let header = match req.headers().get(AUTHORIZATION) {
        Some(h) => h.to_str().unwrap_or(""),
        None => return false,
    };

    if !header.starts_with("Basic ") {
        return false;
    }

    let decoded = general_purpose::STANDARD
        .decode(&header[6..]).unwrap();

    let creds = String::from_utf8_lossy(&decoded);
    let mut parts = creds.splitn(2, ':');
    let user = parts.next().unwrap_or("");
    let pass = parts.next().unwrap_or("");

    let content = std::fs::read_to_string(userfile).unwrap();

    for line in content.lines() {
        if let Some((u, p)) = line.split_once(':') {
            if u == user && verify_password(pass, p) {
                return true;
            }
        }
    }
    false
}

fn verify_password(pass: &str, stored: &str) -> bool {
    if stored.starts_with("{SHA}") {
        let mut hasher = Sha1::new();
        hasher.update(pass.as_bytes());
        let hash = hasher.finalize();
        let encoded = general_purpose::STANDARD.encode(hash);
        encoded == stored[5..]
    } else {
        pass == stored
    }
}

fn auth_challenge() -> Response<RespBody> {
    let mut r = resp(StatusCode::UNAUTHORIZED, "Unauthorized");
    r.headers_mut().insert(
        "WWW-Authenticate",
        "Basic realm=\"Restricted\"".parse().unwrap()
    );
    r
}

fn resp(code: StatusCode, body: &str) -> Response<RespBody> {
    let mut r = Response::new(Full::new(Bytes::from(body.to_string())));
    *r.status_mut() = code;
    r
}

fn log_request(req: &Request<Incoming>, ip: IpAddr) {
    let now = Local::now().format("%d/%b/%Y:%H:%M:%S %z");
    println!(
        "{} - - [{}] \"{} {}\"",
        ip,
        now,
        req.method(),
        req.uri().path()
    );
}

fn load_tls(cert_path: String, key_path: String) -> Result<TlsAcceptor> {

    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut cert_reader)
            .collect::<Result<_, _>>()?;

    // let mut key_reader = BufReader::new(File::open(key_path)?);
    // let mut keys: Vec<PrivateKeyDer<'static>> =
    //     pkcs8_private_keys(&mut key_reader)
    //         .collect::<Result<_, _>>()?;

    // let key = keys.remove(0);




    let mut key_reader = BufReader::new(File::open(key_path)?);

    let key = pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private key found"))??;

    let key = PrivateKeyDer::Pkcs8(key);







    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}


