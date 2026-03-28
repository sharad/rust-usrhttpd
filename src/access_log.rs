use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    sync::Mutex,
};
use hyper::Request;
use hyper::body::Incoming;
use chrono::Local;

pub struct AccessLogger {
    enabled: bool,
    file: Mutex<std::fs::File>,
}

impl AccessLogger {

    pub fn new(path: Option<&str>) -> std::io::Result<Self> {
        if let Some(p) = path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)?;   // ✅ FIXED

            Ok(Self {
                enabled: true,
                file: Mutex::new(file),
            })
        } else {
            Ok(Self {
                enabled: false,
                file: Mutex::new(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("/dev/null")?
                ),
            })
        }
    }

    pub fn log(&self, req: &Request<Incoming>, remote: SocketAddr) {

        if !self.enabled {
            return;
        }
        let line = format!(
            "{} - - [{}] \"{} {}\" \n",
            remote.ip(),
            Local::now().format("%d/%b/%Y:%H:%M:%S %z"),
            req.method(),
            req.uri().path(),
        );

        let mut f = self.file.lock().unwrap();
        let _ = f.write_all(line.as_bytes());
    }
}


