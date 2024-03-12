use crate::utility::*;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;

pub async fn request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    println!("req: {:?}", req);

    match req.method().to_string().to_uppercase().as_str() {
        "CACHE" => {
            let host = match req.uri().host() {
                None => return react_bad_request(),
                Some(x) => x,
            };

            let scheme = req.uri().scheme_str().unwrap_or("HTTP");
            let port = req.uri().port_u16().unwrap_or(default_port(scheme));

            let sender = build_sender(host, port).await;

            let mut req = req;
            *req.method_mut() = Method::HEAD;

            let resp = sender?.send_request(req).await?;
            cache(resp)
        }
        "CONNECT" => {
            if let Some(addr) = host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = tunnel(upgraded, addr).await {
                                eprintln!("server io error: {}", e);
                            };
                        }
                        Err(e) => eprintln!("upgrade error: {}", e),
                    }
                });

                Ok(Response::new(empty()))
            } else {
                react_bad_request_msg("CONNECT must be to a socket address\n".into())
            }
        }
        "GET" => {
            let host = match req.uri().host() {
                None => {
                    return react_bad_request_msg(
                        "Use this address in the 'http_proxy' environment variable instead\n"
                            .into(),
                    )
                }
                Some(x) => x,
            };

            let scheme = req.uri().scheme_str().unwrap_or("HTTP");
            let port = req.uri().port_u16().unwrap_or(default_port(scheme));

            let sender = build_sender(host, port).await;

            let mut req = req;
            *req.method_mut() = Method::HEAD;

            let resp = sender?.send_request(req).await?;
            cache(resp)
        }
        "OPTIONS" => {
            let mut options = Response::new(empty());

            options
                .headers_mut()
                .append("Allow", "CACHE, GET, HEAD".parse().unwrap());

            Ok(options)
        }
        _ => {
            let mut unsupported = Response::new(empty());
            *unsupported.status_mut() = StatusCode::METHOD_NOT_ALLOWED;

            unsupported
                .headers_mut()
                .append("Allow", "CACHE, GET, HEAD".parse().unwrap());

            Ok(unsupported)
        }
    }
}
