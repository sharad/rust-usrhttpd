// src/proxy/cmd.rs

use std::{
    collections::HashMap,
    path::Path,
    process::Stdio,
    sync::Arc,
    time::{Instant, Duration},
};

use once_cell::sync::Lazy;
use tokio::{
    process::{Child, Command},
    sync::RwLock,
};


pub struct RunningProxyCmd {
    pub child: Child,
    pub last_access: Instant,
    pub ttl_secs: u64,
}

pub static PROC_MAP: Lazy<
    Arc<RwLock<HashMap<String, RunningProxyCmd>>>
> = Lazy::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
});

pub async fn ensure_running(
    prefix: &str,
    target: &str,
    ttl: u64,
    command: &str,
    root: &Path,
) {
    {
        let mut map = PROC_MAP.write().await;

        if let Some(proc) = map.get_mut(prefix) {
            proc.last_access = Instant::now();
            return;
        }
    }

    let expanded = expand_command(
        command,
        prefix,
        target,
        root,
    );

    tracing::info!(
        prefix = %prefix,
        command = %expanded,
        "starting ProxyCmdPass process"
    );

    // [dependencies]
    //     shell-words = "1"
    // use shell_words;
    let mut parts = shell_words::split(&expanded)
        .unwrap_or_else(|_| vec![expanded.clone()]);

    // let mut parts: Vec<String> =
    //     expanded.split_whitespace()
    //     .map(|s| s.to_string())
    //     .collect();


    if parts.is_empty() {
        return;
    }

    let program = parts.remove(0);

    let child = match Command::new(&program)
        .args(&parts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "failed to spawn {}: {}",
                program,
                e
            );
            return;
        }
    };

    let mut map = PROC_MAP.write().await;

    map.insert(
        prefix.to_string(),
        RunningProxyCmd {
            child,
            last_access: Instant::now(),
            ttl_secs: ttl,
        },
    );
}



fn expand_command(
    command: &str,
    prefix: &str,
    target: &str,
    root: &Path,
) -> String {
    let uri =
        target.parse::<hyper::Uri>().ok();

    let host =
        uri.as_ref()
        .and_then(|u| u.host())
        .unwrap_or("");

    let port =
        uri.as_ref()
        .and_then(|u| u.port_u16())
        .map(|p| p.to_string())
        .unwrap_or_default();

    command
        .replace("%D", prefix)
        .replace("%U", target)
        .replace("%H", host)
        .replace("%P", &port)
        .replace("%R", &root.display().to_string())
}



pub async fn cleanup_expired() {
    let mut map = PROC_MAP.write().await;

    let now = Instant::now();

    let mut expired = Vec::new();

    for (key, proc) in map.iter() {
        if now
            .duration_since(proc.last_access)
            .as_secs()
            > proc.ttl_secs
        {
            expired.push(key.clone());
        }
    }

    for key in expired {
        if let Some(mut proc) = map.remove(&key) {

            tracing::info!(
                prefix = %key,
                "stopping expired ProxyCmdPass process"
            );

            let _ = proc.child.kill().await;
            let _ = proc.child.wait().await;
        }
    }
}


