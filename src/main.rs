use std::env::args;
use bytes::Bytes;
use http::{header::ALLOW, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{
    client::conn::http1::Builder, server::conn::http1, service::service_fn, upgrade::Upgraded,
    Error, Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    fs::File,
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content_path = get_content_path();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3142));

    let listener = TcpListener::bind(addr).await?;
    println!("Content path {}", content_path.to_str().unwrap());
    println!("Listening on {}", addr.port());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service_fn(proxy))
                .with_upgrades()
                .await
            {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

fn get_content_path() -> PathBuf {
    let path_str = args().nth(1).unwrap_or(String::from("."));

    let path = match Path::new(path_str.as_str()).canonicalize() {
        Ok(p) => {p.to_path_buf()}
        Err(_) => {
            eprintln!("Can't resolve path directory");
            process::exit(1);
        }
    };

    if !path.is_dir() {
        eprintln!("Can't set content path to {:?}", path);
        process::exit(1);
    }
    path
}

fn internal_error() -> Response<BoxBody<Bytes, Error>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(empty())
        .unwrap()
}

async fn send_request(req: Request<Incoming>) -> Result<Response<Incoming>, hyper::Error> {
    let stream = TcpStream::connect((
        req.uri().host().expect("uri has no host"),
        req.uri().port_u16().unwrap_or(80),
    ))
    .await
    .unwrap();

    let io = TokioIo::new(stream);

    let (mut sender, conn) = Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let resp = sender.send_request(req).await?;
    Ok(resp)
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    println!("req: {:?}", req);

    const X_UNIQUE_CACHE_NAME: &str = "x-unique-cache-name";

    match req.method() {
        &Method::CONNECT => {
            if let Some(addr) = host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = upgrade_tunnel(upgraded, addr).await {
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
        &Method::GET => {
            if let Some(cache_name) = req.headers().get(X_UNIQUE_CACHE_NAME) {
                match cache_name.to_str() {
                    Ok(cache_str) => {
                        if Path::new(cache_str).exists() {
                            let mut file = match File::open(cache_str).await {
                                Ok(file) => file,
                                Err(_) => {
                                    return Ok(internal_error());
                                }
                            };

                            let mut contents = Vec::new();
                            file.read_to_end(&mut contents).await.unwrap();

                            let response = hyper::Response::builder()
                                .status(StatusCode::OK)
                                .body(full(contents))
                                .unwrap();
                            return Ok(response);
                        } else {
                            let mut file = match File::create(cache_str).await {
                                Ok(f) => f,
                                Err(_) => {
                                    return Ok(internal_error());
                                }
                            };

                            let mut resp = match send_request(req).await {
                                Ok(r) => r,
                                Err(_) => {
                                    return Ok(internal_error());
                                }
                            };

                            while let Some(next) = resp.frame().await {
                                let frame = next?;
                                if let Some(chunk) = frame.data_ref() {
                                    match file.write_all(&chunk).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            println!("{}", e);
                                            return Ok(internal_error());
                                        }
                                    }
                                }
                            }

                            return Ok(resp.map(|b| b.boxed()));
                        }
                    }
                    Err(e) => println!("Failed to convert cache name to str: {:?}", e),
                }
            }

            let resp = send_request(req).await?;
            Ok(resp.map(|b| b.boxed()))
        }
        _ => {
            let resp = Response::builder()
                .status(405)
                .header(ALLOW, "GET")
                .body(empty())
                .unwrap();
            Ok(resp)
        }
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn upgrade_tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}
