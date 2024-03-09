mod utility;
use utility::*;

use std::net::SocketAddr;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service_fn(handle_request))
                .with_upgrades()
                .await
            {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    println!("req: {:?}", req);

    match req.method().to_string().to_uppercase().as_str() {
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
                eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(full("CONNECT must be to a socket address"));
                *resp.status_mut() = StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        }
        "CACHE" => {
            let host = match req.uri().host() {
                Some(x) => x,
                None => {
                    let mut resp = Response::new(empty());
                    *resp.status_mut() = StatusCode::BAD_REQUEST;

                    return Ok(resp);
                }
            };

            let port = req.uri().port_u16().unwrap_or(80);

            let sender = build_sender(host, port).await;

            let mut req = req;
            *req.method_mut() = Method::GET;

            let resp = sender?.send_request(req).await?;
            Ok(resp.map(|b| b.boxed()))
        }
        "GET" => {
            let host = match req.uri().host() {
                Some(x) => x,
                None => {
                    let mut resp = Response::new(full(
                        "Use this address in the 'http_proxy' environment variable instead\n",
                    ));
                    *resp.status_mut() = StatusCode::OK;
                    return Ok(resp);
                }
            };

            let port = req.uri().port_u16().unwrap_or(80);

            let sender = build_sender(host, port).await;
            let resp = sender?.send_request(req).await?;
            Ok(resp.map(|b| b.boxed()))
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
