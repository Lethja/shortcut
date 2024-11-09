#[cfg(feature = "https")]
mod cert;
mod http;

#[cfg(feature = "https")]
use crate::cert::{setup_certificates, CertificateSetup, CERT_QUERY};
use crate::http::{
    fetch_and_serve_chunk, fetch_and_serve_known_length, get_cache_name, keep_alive_if,
    url_is_http, ConnectionReturn,
    ConnectionReturn::{Close, Keep},
    HttpRequestHeader, HttpRequestMethod, HttpResponseHeader, HttpResponseStatus, HttpVersion,
    BUFFER_SIZE, X_PROXY_CACHE_PATH,
};
#[cfg(feature = "https")]
use crate::ConnectionReturn::Upgrade;
#[cfg(feature = "https")]
use rustls::pki_types::ServerName;
#[cfg(feature = "https")]
use std::convert::TryFrom;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use tokio::{
    fs::{create_dir_all, remove_file, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};

pub(crate) const PKG_NAME: &str = env!("CARGO_PKG_NAME");
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
    let certificates = Arc::new(setup_certificates());

    let http_bind = std::env::var(X_PROXY_HTTP_LISTEN_ADDRESS).unwrap_or("[::]:3142".to_string());

    let http_listener = match TcpListener::bind(&http_bind).await {
        Ok(l) => {
            let details = l.local_addr().unwrap();
            let address = match details.ip().is_unspecified() {
                true => "Any".to_string(),
                false => details.ip().to_string(),
            };
            #[cfg(feature = "https")]
            {
                eprintln!("{PKG_NAME} HTTP(S) listen address: {}", address);
                eprintln!("{PKG_NAME} HTTP(S) listen port: {}", details.port());
            }
            #[cfg(not(feature = "https"))]
            {
                eprintln!("{PKG_NAME} HTTP listen address: {}", address);
                eprintln!("{PKG_NAME} HTTP listen port: {}", details.port());
            }
            l
        }
        Err(e) => {
            eprintln!("Error: unable to bind '{http_bind}': {e}");
            return;
        }
    };
    drop(http_bind);

    let max_connections = std::env::var(X_PROXY_MAX_CONNECTIONS)
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .unwrap_or(16);

    let semaphore = Arc::new(Semaphore::new(max_connections));

    loop {
        listen_for(
            &http_listener,
            &semaphore,
            #[cfg(feature = "https")]
            &certificates,
        )
        .await;
    }
}

async fn listen_for(
    http_listener: &TcpListener,
    semaphore: &Arc<Semaphore>,
    #[cfg(feature = "https")] certificates: &Arc<CertificateSetup>,
) {
    let (mut stream, _) = match http_listener.accept().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Unable to accept new connection: {e}");
            return;
        }
    };

    let semaphore = Arc::clone(semaphore);
    #[cfg(feature = "https")]
    let certificates = Arc::clone(certificates);

    tokio::spawn(async move {
        let _permit = semaphore.acquire().await.expect("Semaphore acquire failed");

        loop {
            match handle_connection(
                &mut stream,
                #[cfg(feature = "https")]
                &certificates,
            )
            .await
            {
                Close => break,
                Keep => continue,
                #[cfg(feature = "https")]
                Upgrade => {
                    match listen_for_https(&mut stream, &certificates).await {
                        Keep => continue,
                        _ => return,
                    }
                }
            }
        }
    });
}

#[cfg(feature = "https")]
async fn listen_for_https(
    stream: &mut TcpStream,
    certificates: &Arc<CertificateSetup>,
) -> ConnectionReturn {

    let acceptor = certificates.server_config.clone();

    let mut stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{PKG_NAME} couldn't create tls stream: {e}");
            return Close;
        }
    };

    loop {
        match handle_connection(
            &mut stream,
            &certificates,
        )
            .await
        {
            Keep => continue,
            _ => break,
        }
    }

    Close
}

async fn handle_connection<T>(
    mut stream: T,
    #[cfg(feature = "https")] cert: &CertificateSetup,
) -> ConnectionReturn
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut client_buf_reader = BufReader::new(&mut stream);

    let client_request_header = match timeout(
        Duration::from_secs(5),
        HttpRequestHeader::from_tcp_buffer_async(&mut client_buf_reader),
    )
    .await
    {
        Ok(c) => match c {
            None => return Close,
            Some(header) => header,
        },
        Err(_) => return Close,
    };

    if client_request_header.method == HttpRequestMethod::Get {
        if client_request_header.has_relative_path() {
            match client_request_header.get_query() {
                #[cfg(feature = "https")]
                Some(q) => {
                    if q == CERT_QUERY {
                        if cert.server_cert_path.is_file() {
                            serve_existing_file(
                                &cert.server_cert_path,
                                stream,
                                client_request_header,
                            )
                            .await;
                        } else {
                            let response = HttpResponseStatus::NOT_FOUND.to_response();
                            stream
                                .write_all(response.as_bytes())
                                .await
                                .unwrap_or_default();
                        }
                    }
                }
                _ => {
                    let response = HttpResponseStatus::NO_CONTENT.to_header();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                }
            };
            Keep
        } else {
            let host = match url_is_http(&client_request_header) {
                None => {
                    let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                    return keep_alive_if(&client_request_header);
                }
                Some(h) => h.to_string(),
            };

            let cache_file_path = match get_cache_name(&client_request_header).await {
                None => return keep_alive_if(&client_request_header),
                Some(p) => p,
            };

            if cache_file_path.exists() {
                serve_existing_file(&cache_file_path, stream, client_request_header).await
            } else {
                #[cfg(feature = "https")]
                return fetch_and_serve_file(
                    cache_file_path,
                    stream,
                    host,
                    client_request_header,
                    cert,
                )
                .await;
                #[cfg(not(feature = "https"))]
                return fetch_and_serve_file(cache_file_path, stream, host, client_request_header)
                    .await;
            }
        }
    } else {
        let response = HttpResponseStatus::METHOD_NOT_ALLOWED.to_response();
        stream
            .write_all(response.as_bytes())
            .await
            .unwrap_or_default();
        Keep
    }
}

async fn serve_existing_file<T>(
    cache_file_path: &PathBuf,
    mut stream: T,
    client_request_header: HttpRequestHeader,
) -> ConnectionReturn
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut file = match File::open(cache_file_path).await {
        Ok(f) => f,
        Err(_) => {
            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default();
            return keep_alive_if(&client_request_header);
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
            return keep_alive_if(&client_request_header);
        }
    };

    let length = metadata.len();
    if length == 0 {
        let response = HttpResponseStatus::NO_CONTENT.to_header();
        stream
            .write_all(response.as_bytes())
            .await
            .unwrap_or_default();
        return keep_alive_if(&client_request_header);
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

    if end_position <= start_position {
        let response = HttpResponseStatus::BAD_REQUEST.to_response();
        stream
            .write_all(response.as_bytes())
            .await
            .unwrap_or_default();
        return keep_alive_if(&client_request_header);
    }

    let mut bytes: u64 = end_position - start_position + 1;

    while bytes > 0 {
        let bytes_to_read = std::cmp::min(BUFFER_SIZE as u64, bytes) as usize;
        match file.read(&mut buffer[..bytes_to_read]).await {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buffer[..n]).await.is_err() {
                    return Close;
                }
                bytes -= n as u64;
            }
            Err(_) => break,
        }
    }
    keep_alive_if(&client_request_header)
}

async fn fetch_and_serve_file<T>(
    cache_file_path: PathBuf,
    mut stream: T,
    host: String,
    client_request_header: HttpRequestHeader,
    #[cfg(feature = "https")] certificates: &CertificateSetup,
) -> ConnectionReturn
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    async fn fetch<R, S>(
        cache_file_path: PathBuf,
        client_request_header: HttpRequestHeader,
        host: String,
        fetch_buf_reader: &mut BufReader<&mut R>,
        mut stream: &mut S,
    ) -> ConnectionReturn
    where
        R: AsyncReadExt + AsyncWriteExt + Unpin,
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let fetch_request = HttpRequestHeader {
            method: HttpRequestMethod::Get,
            path: client_request_header.get_path_without_query().to_string(),
            version: HttpVersion::from(&client_request_header.version.as_str()),
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
                return keep_alive_if(&client_request_header);
            }
        }

        let mut fetch_response_header =
            match HttpResponseHeader::from_tcp_buffer_async(fetch_buf_reader).await {
                None => {
                    eprintln!("Error: unable to extract header from '{host}'");
                    let response = HttpResponseStatus::BAD_GATEWAY.to_response();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                    return keep_alive_if(&client_request_header);
                }
                Some(s) => s,
            };

        let fetch_response_header_data = fetch_response_header.generate();

        match stream
            .write_all(fetch_response_header_data.as_bytes())
            .await
        {
            Ok(_) => {}
            Err(_) => return Close,
        }

        if fetch_response_header.status.to_code() == 200 {
            let cache_file_parent = match cache_file_path.parent() {
                None => {
                    let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                    return keep_alive_if(&client_request_header);
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
                    return keep_alive_if(&client_request_header);
                }
                Ok(file) => file,
            };

            let (write_stream, write_file);

            if let Some(v) = fetch_response_header.headers.get("Transfer-Encoding") {
                if v.to_lowercase() == "chunked" {
                    (write_stream, write_file) = fetch_and_serve_chunk(
                        &cache_file_path,
                        &mut stream,
                        fetch_buf_reader,
                        &mut file,
                    )
                    .await
                } else {
                    let response = HttpResponseStatus::BAD_REQUEST.to_response();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                    return keep_alive_if(&client_request_header);
                }
            } else {
                let content_length = match fetch_response_header.headers.get("Content-Length") {
                    None => {
                        let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                        stream
                            .write_all(response.as_bytes())
                            .await
                            .unwrap_or_default();
                        return keep_alive_if(&client_request_header);
                    }
                    Some(s) => match s.parse::<u64>() {
                        Ok(u) => u,
                        Err(_) => {
                            let response = HttpResponseStatus::BAD_REQUEST.to_response();
                            stream
                                .write_all(response.as_bytes())
                                .await
                                .unwrap_or_default();
                            return keep_alive_if(&client_request_header);
                        }
                    },
                };

                (write_stream, write_file) = fetch_and_serve_known_length(
                    &cache_file_path,
                    &mut stream,
                    content_length,
                    &mut *fetch_buf_reader,
                    &mut file,
                )
                .await;
            }

            let _ = timeout(Duration::from_millis(100), fetch_buf_reader.shutdown()).await;

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
            } else if cache_file_path.is_file() {
                /* Something has gone wrong, undefined state */
                let _ = remove_file(cache_file_path).await;
                return Close;
            }
            keep_alive_if(&client_request_header)
        } else {
            let pass_through = fetch_response_header.generate();
            let _ = stream.write_all(pass_through.as_bytes()).await;
            keep_alive_if(&client_request_header)
        }
    }

    let mut fetch_stream = match TcpStream::connect(&host).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: unable to connect to '{host}': {e}");
            let response = HttpResponseStatus::BAD_GATEWAY.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default();
            return keep_alive_if(&client_request_header);
        }
    };

    #[cfg(feature = "https")]
    if client_request_header
        .get_scheme()
        .is_some_and(|s| s == "https")
    {
        let host_str = host.clone();

        let domain = match ServerName::try_from(host_str) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{PKG_NAME} couldn't domain name: {e}");
                return Close;
            }
        };

        let mut fetch_stream = match certificates
            .client_config
            .connect(domain, fetch_stream)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{PKG_NAME} couldn't establish HTTPS connection to {host}: {e}");
                return Close;
            }
        };

        let mut fetch_buf_reader = BufReader::new(&mut fetch_stream);
        fetch(
            cache_file_path,
            client_request_header,
            host,
            &mut fetch_buf_reader,
            &mut stream,
        )
        .await;
        return Upgrade;
    }

    let mut fetch_buf_reader = BufReader::new(&mut fetch_stream);
    fetch(
        cache_file_path,
        client_request_header,
        host,
        &mut fetch_buf_reader,
        &mut stream,
    )
    .await
}
