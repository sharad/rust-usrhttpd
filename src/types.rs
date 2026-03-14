use bytes::Bytes;
use http_body_util::combinators::BoxBody;

pub type RespBody = BoxBody<Bytes, hyper::Error>;
