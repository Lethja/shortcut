use bytes::Bytes;
use http::{
    header::{ALLOW, CONTENT_RANGE, RANGE},
    StatusCode,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Incoming, client::conn::http1::Builder, server::conn::http1, service::service_fn,
    upgrade::Upgraded, Error, Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use std::{
    env::args,
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
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

fn parse_range_header(range_header: &str, file_size: u64) -> Option<(u64, u64)> {
    if let Some(range_str) = range_header.strip_prefix("bytes=") {
        if let Some((start_str, end_str)) = range_str.split_once('-') {
            let start = if start_str.is_empty() {
                /* If start_str is empty, it means the start is unspecified (suffix range) */
                0
            } else {
                start_str.parse::<u64>().ok()?
            };

            let end = if end_str.is_empty() {
                /* If end_str is empty, it means the end is unspecified (prefix range) */
                file_size - 1
            } else {
                end_str.parse::<u64>().ok()?
            };

            if start <= end && end < file_size {
                return Some((start, end));
            }
        }
    }
    None
}

fn get_content_path() -> PathBuf {
    let path_str = args().nth(1).unwrap_or(String::from("."));

    let path = match Path::new(path_str.as_str()).canonicalize() {
        Ok(p) => p.to_path_buf(),
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

async fn send_request(req: Request<Incoming>) -> Result<Response<Incoming>, Error> {
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

fn try_get_request_file_name(req: &Request<Incoming>) -> Option<String> {
    use http::header::CONTENT_DISPOSITION;

    if let Ok(name) = req.headers().get(CONTENT_DISPOSITION)?.to_str() {
        for part in name.split(';').map(str::trim) {
            if part.starts_with("filename=") {
                let file_name = part.split_at("filename=".len()).1.trim_matches('"');
                return Some(file_name.to_string());
            } else if part.starts_with("filename*=") {
                let file_name = part.split_at("filename*=".len()).1.trim_matches('"');
                return Some(file_name.to_string());
            }
        }
    }

    const X_UNIQUE_CACHE_NAME: &str = "x-unique-cache-name";

    if let Ok(name) = req.headers().get(X_UNIQUE_CACHE_NAME)?.to_str() {
        return Some(name.to_string());
    }

    req.uri().path().rsplit('/').next().and_then(|segment| {
        if segment.contains('.') {
            return Some(segment);
        }
        None
    });

    None
}

async fn proxy(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    println!("req: {:?}", req);

    match *req.method() {
        Method::CONNECT => {
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
        Method::GET => {
            if let Some(cache_name) = try_get_request_file_name(&req) {
                let file_path = get_content_path().join(cache_name);
                return if file_path.is_file() {
                    let mut file = match File::open(file_path).await {
                        Ok(file) => file,
                        Err(_) => {
                            return Ok(internal_error());
                        }
                    };

                    if let Some(r) = req.headers().get(RANGE) {
                        let meta = match file.metadata().await {
                            Ok(m) => m,
                            Err(_) => {
                                return Ok(internal_error());
                            }
                        };

                        if let Some((start, end)) =
                            parse_range_header(r.to_str().unwrap(), meta.len())
                        {
                            let mut buffer = vec![0; (end - start + 1) as usize];

                            file.seek(tokio::io::SeekFrom::Start(start)).await.unwrap();
                            file.read_exact(&mut buffer[..]).await.unwrap();

                            return Ok(Response::builder()
                                .status(StatusCode::PARTIAL_CONTENT)
                                .header(
                                    CONTENT_RANGE,
                                    format!("bytes {}-{}/{}", start, end, meta.len()).as_bytes(),
                                )
                                .body(full(buffer))
                                .unwrap());
                        }
                    }

                    let mut contents = Vec::new();
                    file.read_to_end(&mut contents).await.unwrap();

                    let response = hyper::Response::builder()
                        .status(StatusCode::OK)
                        .body(full(contents))
                        .unwrap();
                    Ok(response)
                } else {
                    /* Remove content range as the proxy needs to cache the file */
                    let mut req = req;
                    req.headers_mut().remove(CONTENT_RANGE);

                    let mut file = match File::create(file_path).await {
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
                            match file.write_all(chunk).await {
                                Ok(_) => {}
                                Err(e) => {
                                    println!("{}", e);
                                    return Ok(internal_error());
                                }
                            }
                        }
                    }

                    Ok(resp.map(|b| b.boxed()))
                };
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
    uri.authority().map(|auth| auth.to_string())
}

fn empty() -> BoxBody<Bytes, Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Error> {
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
