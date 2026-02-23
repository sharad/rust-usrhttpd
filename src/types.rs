// use bytes::Bytes;
// use http_body_util::combinators::BoxBody;
// use std::convert::Infallible;

// pub type RespBody = BoxBody<Bytes, Infallible>;



use bytes::Bytes;
use http_body_util::combinators::BoxBody;

pub type RespBody = BoxBody<Bytes, hyper::Error>;
