
use clap::Parser;

/// CLI arguments (raw, may be partial)
/// All fields are Option<T> so we can merge properly with config file.
#[derive(Parser, Debug, Clone)]
#[command(name = "usrhttpd")]
#[command(about = "Minimal HTTP server with htaccess + proxy support")]
pub struct Args {
    /// Root directory to serve
    #[arg()]
    pub root: Option<String>,

    /// Host to bind
    #[arg(short = 'H', long)]
    pub host: Option<String>,

    /// Port to listen on
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// TLS certificate path
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    pub tls_key: Option<String>,

    /// Path to config file
    #[arg(long)]
    pub config: Option<String>,
}


