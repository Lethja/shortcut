#[cfg(feature = "https")]
mod cert;
mod http;

#[cfg(feature = "https")]
use crate::cert::{CERT_QUERY, check_or_create_tls};
use crate::http::{
    fetch_and_serve_chunk, fetch_and_serve_known_length, get_cache_name, url_is_http,
    HttpRequestHeader, HttpRequestMethod, HttpResponseHeader, HttpResponseStatus, HttpVersion,
    BUFFER_SIZE, X_PROXY_CACHE_PATH,
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    fs::{create_dir_all, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

const X_PROXY_HTTP_LISTEN_ADDRESS: &str = "X_PROXY_HTTP_LISTEN_ADDRESS";
const X_PROXY_MAX_CONNECTIONS: &str = "X_PROXY_MAX_CONNECTIONS";

#[tokio::main]
async fn main() {
    eprintln!("{PKG_NAME} version: {PKG_VERSION}");
    match std::env::var(X_PROXY_CACHE_PATH) {
        Ok(s) => {
            let path = PathBuf::from(&s);
            if !path.exists() {
                if let Err(e) = create_dir_all(&path).await {
                    eprintln!("Error: couldn't create directory '{s}': {e}");
                    return;
                }
            }
            eprintln!("{PKG_NAME} cache path: {s}");
        }
        Err(_) => {
            eprintln!("Error: '{X_PROXY_CACHE_PATH}' has not been set");
            return;
        }
    };

    #[cfg(feature = "https")]
    let (cert, _) = check_or_create_tls();

    let bind = std::env::var(X_PROXY_HTTP_LISTEN_ADDRESS).unwrap_or("[::]:3142".to_string());

    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => {
            let details = l.local_addr().unwrap();
            let address = match details.ip().is_unspecified() {
                true => "Any".to_string(),
                false => details.ip().to_string(),
            };
            eprintln!("{PKG_NAME} HTTP listen address: {}", address);
            eprintln!("{PKG_NAME} HTTP listen port: {}", details.port());
            l
        }
        Err(e) => {
            eprintln!("Error: unable to bind '{bind}': {e}");
            return;
        }
    };
    drop(bind);

    let max_connections = std::env::var(X_PROXY_MAX_CONNECTIONS)
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .unwrap_or(16);

    let semaphore = Arc::new(Semaphore::new(max_connections));

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: Unable to accept new connection: {e}");
                continue;
            }
        };

        let semaphore = Arc::clone(&semaphore);
        #[cfg(feature = "https")]
        let cert = PathBuf::from(&cert);

        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.expect("Semaphore acquire failed");

            handle_connection(
                stream,
                #[cfg(feature = "https")]
                cert,
            )
            .await;
        });
    }
}

async fn handle_connection(mut stream: TcpStream, #[cfg(feature = "https")] cert: PathBuf) {
    let mut client_buf_reader = BufReader::new(&mut stream);
    let client_request_header =
        match HttpRequestHeader::from_tcp_buffer_async(&mut client_buf_reader).await {
            None => return,
            Some(header) => header,
        };

    if let HttpRequestMethod::Get = client_request_header.method {
        if client_request_header.has_relative_path() {
            match client_request_header.get_query() {
                #[cfg(feature = "https")]
                None => {
                    let response = HttpResponseStatus::NO_CONTENT.to_header();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                }
                #[cfg(feature = "https")]
                Some(q) => {
                    if q == CERT_QUERY {
                        if cert.is_file() {
                            serve_existing_file(cert, stream, client_request_header).await;
                        }
                    }
                }
                #[cfg(not(feature = "https"))]
                _ => {
                    let response = HttpResponseStatus::NO_CONTENT.to_header();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                }
            };
        } else {
            let host = match url_is_http(&client_request_header) {
                None => {
                    let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                    return;
                }
                Some(h) => h.to_string(),
            };

            let cache_file_path = match get_cache_name(&client_request_header).await {
                None => return,
                Some(p) => p,
            };

            if cache_file_path.exists() {
                serve_existing_file(cache_file_path, stream, client_request_header).await
            } else {
                fetch_and_serve_file(cache_file_path, stream, host, client_request_header).await
            }
        }
    }
}

async fn serve_existing_file(
    cache_file_path: PathBuf,
    mut stream: TcpStream,
    client_request_header: HttpRequestHeader,
) {
    let mut file = match File::open(cache_file_path).await {
        Ok(f) => f,
        Err(_) => {
            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default();
            return;
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => {
            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default();
            return;
        }
    };

    let length = metadata.len();
    if length == 0 {
        let response = HttpResponseStatus::NO_CONTENT.to_header();
        stream
            .write_all(response.as_bytes())
            .await
            .unwrap_or_default();
        return;
    }

    let mut start_position: u64 = 0;
    let mut end_position: u64 = length - 1;

    let mut status = HttpResponseStatus::OK;
    let mut headers = HashMap::<String, String>::new();
    headers.insert(String::from("Content-Length"), metadata.len().to_string());

    match client_request_header.headers.get("Range") {
        None => {}
        Some(range) => {
            let range = range.trim();
            if let Some(bytes) = range.strip_prefix("bytes=") {
                let mut iter = bytes.split('-');
                if let (Some(start), Some(end)) = (iter.next(), iter.next()) {
                    start_position = start.parse::<u64>().unwrap_or(0);
                    end_position = end.parse::<u64>().unwrap_or(length - 1);
                    if end_position > start_position {
                        headers.insert(
                            String::from("Content-Range"),
                            format!("bytes={start_position}-{end_position}/{length}"),
                        );
                        status = HttpResponseStatus::PARTIAL_CONTENT;
                    }
                }
            }
        }
    }

    let mut header = HttpResponseHeader {
        status,
        headers,
        version: HttpVersion::HTTP_V11,
    };

    let header = header.generate();
    let _ = stream.write_all(header.as_ref()).await;
    let mut buffer = vec![0; BUFFER_SIZE];
    let _ = file.seek(SeekFrom::Start(start_position)).await;
    let mut bytes: u64 = end_position - start_position + 1;

    while bytes > 0 {
        let bytes_to_read = std::cmp::min(BUFFER_SIZE as u64, bytes) as usize;
        match file.read(&mut buffer[..bytes_to_read]).await {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
                bytes -= n as u64;
            }
            Err(_) => break,
        }
    }
}

async fn fetch_and_serve_file(
    cache_file_path: PathBuf,
    mut stream: TcpStream,
    host: String,
    client_request_header: HttpRequestHeader,
) {
    let mut fetch_stream = match TcpStream::connect(&host).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: unable to connect to '{host}': {e}");
            let response = HttpResponseStatus::BAD_GATEWAY.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default();
            return;
        }
    };

    let mut fetch_buf_reader = BufReader::new(&mut fetch_stream);

    let fetch_request = HttpRequestHeader {
        method: HttpRequestMethod::Get,
        path: client_request_header.get_path_without_query().to_string(),
        version: client_request_header.version,
        headers: {
            let mut headers = client_request_header.headers.clone();
            headers.remove("Range"); /* Not cached so need to download from start */
            headers
        },
    };

    let fetch_request_data = fetch_request.generate();

    match fetch_buf_reader
        .write_all(fetch_request_data.as_bytes())
        .await
    {
        Ok(_) => {}
        Err(_) => {
            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default();
        }
    }

    let mut fetch_response_header =
        match HttpResponseHeader::from_tcp_buffer_async(&mut fetch_buf_reader).await {
            None => {
                eprintln!("Error: unable to extract header from '{host}'");
                let response = HttpResponseStatus::BAD_GATEWAY.to_response();
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_default();
                return;
            }
            Some(s) => s,
        };

    let fetch_response_header_data = fetch_response_header.generate();

    match stream
        .write_all(fetch_response_header_data.as_bytes())
        .await
    {
        Ok(_) => {}
        Err(_) => return,
    }

    if fetch_response_header.status.to_code() == 200 {
        let cache_file_parent = match cache_file_path.parent() {
            None => {
                let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_default();
                return;
            }
            Some(p) => p,
        };
        match create_dir_all(cache_file_parent).await {
            Ok(_) => {}
            Err(_) => {
                let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_default();
            }
        }
        let mut file = match File::create(&cache_file_path).await {
            Err(_) => {
                let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_default();
                return;
            }
            Ok(file) => file,
        };

        let (write_stream, write_file);

        if let Some(v) = fetch_response_header.headers.get("Transfer-Encoding") {
            if v.to_lowercase() == "chunked" {
                (write_stream, write_file) =
                    fetch_and_serve_chunk(cache_file_path, &mut stream, fetch_buf_reader, &mut file)
                        .await
            } else {
                let response = HttpResponseStatus::BAD_REQUEST.to_response();
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_default();
                return;
            }
        } else {
            let content_length = match fetch_response_header.headers.get("Content-Length") {
                None => {
                    let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                    return;
                }
                Some(s) => match s.parse::<u64>() {
                    Ok(u) => u,
                    Err(_) => {
                        let response = HttpResponseStatus::BAD_REQUEST.to_response();
                        stream
                            .write_all(response.as_bytes())
                            .await
                            .unwrap_or_default();
                        return;
                    }
                },
            };

            (write_stream, write_file) = fetch_and_serve_known_length(
                cache_file_path,
                &mut stream,
                content_length,
                fetch_buf_reader,
                &mut file,
            )
            .await;
        }

        let _ = timeout(Duration::from_millis(100), fetch_stream.shutdown()).await;

        if write_stream {
            let _ = timeout(Duration::from_millis(100), stream.shutdown()).await;
        }

        if write_file {
            if let Some(last_modified) = fetch_response_header.headers.get("Last-Modified") {
                if let Ok(last_modified) = httpdate::parse_http_date(last_modified) {
                    let _ = timeout(
                        Duration::from_millis(100),
                        tokio::spawn(async move {
                            let _ = file.into_std().await.set_modified(last_modified);
                        }),
                    )
                    .await;
                }
            }
        }
    } else {
        let pass_through = fetch_response_header.generate();
        let _ = stream.write_all(pass_through.as_bytes()).await;
    }
}
