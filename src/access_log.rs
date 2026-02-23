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
    file: Mutex<std::fs::File>,
}

impl AccessLogger {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn log(&self, req: &Request<Incoming>, remote: SocketAddr) {
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


