mod utility;
use utility::*;

use std::net::SocketAddr;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

async fn serve_cache(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    /* TODO: Connect to the remote HTTP(s) address if one is specified */
    println!("({}){}", req.uri().scheme_str().unwrap_or_default(), req.uri().to_string());

    let mut tbd = Response::new(empty());
    *tbd.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    Ok(tbd)
}

async fn serve(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match req.method().as_str().to_uppercase().as_str() {
        "CACHE" => serve_cache(req).await,
        "GET" => serve_cache(req).await,
        "OPTIONS" => {
            let mut options = Response::new(empty());
            options.headers_mut().append("Allow", "CACHE, GET, HEAD".parse().unwrap());
            Ok(options)
        },

        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(serve))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
