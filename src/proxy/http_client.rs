

use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper::body::Incoming;
use once_cell::sync::Lazy;


pub static HTTP_CLIENT: Lazy<Client<HttpConnector, Incoming>> = Lazy::new(|| {
    let connector = HttpConnector::new();
    Client::builder(TokioExecutor::new()).build(connector)
});


