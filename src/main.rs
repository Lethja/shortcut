#[cfg(feature = "https")]
mod cert;
mod conn;
mod http;

#[cfg(feature = "https")]
use crate::{
    cert::{setup_certificates, CertificateSetup, CERT_QUERY},
    ConnectionReturn::Upgrade,
};
#[cfg(feature = "https")]
use tokio::net::TcpStream;

use crate::{
    conn::{Uri, FetchRequest},
    http::{
        fetch_and_serve_chunk, fetch_and_serve_known_length, get_cache_name, keep_alive_if,
        ConnectionReturn,
        ConnectionReturn::{Close, Keep, Redirect},
        HttpRequestHeader, HttpRequestMethod, HttpResponseHeader, HttpResponseStatus, HttpVersion,
        BUFFER_SIZE, X_PROXY_CACHE_PATH,
    },
};

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    fs::{create_dir_all, remove_file, File},
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader, SeekFrom},
    net::TcpListener,
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
        .ok()
        .and_then(|s| s.parse().ok())
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

        #[cfg(feature = "https")]
        let mut fetch_request: Option<conn::FetchRequest> = None;

        #[cfg(feature = "https")]
        loop {
            match handle_connection(&mut stream, &certificates, &mut fetch_request).await {
                Keep => continue,
                Upgrade(mut s) => {
                    s.insert_str(0, "https://");
                    let new_uri = Uri::from(s);
                    fetch_request = match fetch_request {
                        Some(mut f) => {
                            match f.redirect(&new_uri, &certificates).await {
                                Ok(o) => o,
                                Err(_) => return Close,
                            }
                            Some(f)
                        }
                        None => match FetchRequest::from_uri(&new_uri) {
                            Ok(o) => Some(o),
                            Err(_) => None,
                        },
                    };

                    match listen_for_https(&mut stream, &certificates, &mut fetch_request).await {
                        Keep => continue,
                        x => return x,
                    }
                }
                x => return x,
            }
        }

        #[cfg(not(feature = "https"))]
        while let Keep = handle_connection(&mut stream).await {}
    });
}

#[cfg(feature = "https")]
async fn listen_for_https(
    stream: &mut TcpStream,
    certificates: &Arc<CertificateSetup>,
    mut fetch_request: &mut Option<conn::FetchRequest<'_>>,
) -> ConnectionReturn {
    let acceptor = certificates.server_config.clone();

    let mut stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{PKG_NAME} couldn't create tls stream: {e}");
            return Close;
        }
    };

    while let Keep = handle_connection(&mut stream, certificates, &mut fetch_request).await {}

    Close
}

async fn handle_connection<T>(
    mut stream: T,
    #[cfg(feature = "https")] cert: &CertificateSetup,
    mut fetch_request: &mut Option<FetchRequest<'_>>,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
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

    match client_request_header.method {
        HttpRequestMethod::Get => match client_request_header.request.kind() {
            conn::UriKind::AbsolutePath => {
                match client_request_header.request.query {
                    #[cfg(feature = "https")]
                    Some(q) => {
                        if q == CERT_QUERY {
                            if cert.server_cert_path.is_file() {
                                serve_existing_file(
                                    &cert.server_cert_path,
                                    stream,
                                    &client_request_header,
                                )
                                .await;
                            } else {
                                let response = HttpResponseStatus::NOT_FOUND.to_response();
                                if stream.write_all(response.as_bytes()).await.is_err() {
                                    return Close;
                                }
                            }
                        }
                    }
                    #[cfg(feature = "https")]
                    _ => match fetch_request {
                        None => {
                            let response = HttpResponseStatus::NO_CONTENT.to_empty_response();
                            if stream.write_all(response.as_bytes()).await.is_err() {
                                return Close;
                            }
                        }
                        Some(_) => {
                            let cache_file_path = match get_cache_name(&client_request_header).await
                            {
                                None => return keep_alive_if(&client_request_header),
                                Some(p) => p,
                            };

                            if cache_file_path.exists() {
                                serve_existing_file(
                                    &cache_file_path,
                                    stream,
                                    &client_request_header,
                                )
                                .await
                            } else {
                                return fetch_and_serve_file(
                                    cache_file_path,
                                    stream,
                                    client_request_header,
                                    &mut fetch_request,
                                    cert,
                                )
                                .await;
                            };
                        }
                    },
                    #[cfg(not(feature = "https"))]
                    _ => {
                        let response = HttpResponseStatus::NO_CONTENT.to_empty_response();
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return Close;
                        }
                    }
                }
                keep_alive_if(&client_request_header)
            }
            _ => {
                let cache_file_path = match get_cache_name(&client_request_header).await {
                    None => return keep_alive_if(&client_request_header),
                    Some(p) => p,
                };

                if cache_file_path.exists() {
                    serve_existing_file(&cache_file_path, stream, &client_request_header).await
                } else {
                    #[cfg(feature = "https")]
                    return fetch_and_serve_file(
                        cache_file_path,
                        stream,
                        client_request_header,
                        &mut fetch_request,
                        cert,
                    )
                    .await;
                    #[cfg(not(feature = "https"))]
                    return fetch_and_serve_file(cache_file_path, stream, client_request_header)
                        .await;
                }
            }
        },
        #[cfg(feature = "https")]
        HttpRequestMethod::Connect => {
            match (
                client_request_header.request.host,
                client_request_header.request.port,
            ) {
                (Some(_), Some(_)) => {
                    let response = HttpResponseStatus::OK.to_empty_response();
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return Close;
                    }
                    Upgrade(client_request_header.request.uri)
                },
                _ => {
                    let response = HttpResponseStatus::BAD_REQUEST.to_empty_response();
                    let _ = stream.write_all(response.as_bytes()).await;
                    Close
                }
            }
        }
        _ => {
            let response = HttpResponseStatus::METHOD_NOT_ALLOWED.to_response();
            if stream.write_all(response.as_bytes()).await.is_err() {
                return Close;
            }
            keep_alive_if(&client_request_header)
        }
    }
}

async fn serve_existing_file<T>(
    cache_file_path: &PathBuf,
    mut stream: T,
    client_request_header: &HttpRequestHeader<'_>,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = match File::open(cache_file_path).await {
        Ok(f) => f,
        Err(_) => {
            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
            if stream.write_all(response.as_bytes()).await.is_err() {
                return Close;
            }
            return keep_alive_if(client_request_header);
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => {
            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
            if stream.write_all(response.as_bytes()).await.is_err() {
                return Close;
            }
            return keep_alive_if(client_request_header);
        }
    };

    let length = metadata.len();
    if length == 0 {
        let response = HttpResponseStatus::NO_CONTENT.to_empty_response();
        if stream.write_all(response.as_bytes()).await.is_err() {
            return Close;
        }
        return keep_alive_if(client_request_header);
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
        if stream.write_all(response.as_bytes()).await.is_err() {
            return Close;
        }
        return keep_alive_if(client_request_header);
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
    keep_alive_if(client_request_header)
}

async fn fetch_and_serve_file<T>(
    cache_file_path: PathBuf,
    mut stream: T,
    client_request_header: HttpRequestHeader<'_>,
    #[cfg(feature = "https")] fetch_request: &mut Option<FetchRequest<'_>>,
    #[cfg(feature = "https")] certificates: &CertificateSetup,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let uri = match fetch_request {
        None => Uri::from(&client_request_header.request),
        Some(u) => u.uri().merge_with(&client_request_header.request),
    };

    let mut fetch_request = match conn::FetchRequest::from_uri(&uri) {
        Ok(r) => r,
        Err(e) => {
            let response = match e {
                _ => HttpResponseStatus::BAD_REQUEST,
            };
            if stream
                .write_all(response.to_response().as_bytes())
                .await
                .is_err()
            {
                return Close;
            }
            return keep_alive_if(&client_request_header);
        }
    };

    if let Err(e) = fetch_request
        .connect(
            #[cfg(feature = "https")]
            certificates,
        )
        .await
    {
        eprintln!("Fetch connect error: {}", e);
        let response = match e {
            _ => HttpResponseStatus::BAD_REQUEST,
        };
        if stream
            .write_all(response.to_response().as_bytes())
            .await
            .is_err()
        {
            return Close;
        }
        return keep_alive_if(&client_request_header);
    }

    let mut fetch_stream = match fetch_request.as_stream() {
        None => {
            if stream
                .write_all(
                    HttpResponseStatus::INTERNAL_SERVER_ERROR
                        .to_response()
                        .as_bytes(),
                )
                .await
                .is_err()
            {
                return Close;
            }
            return keep_alive_if(&client_request_header);
        }
        Some(f) => f,
    };

    let mut uri = Uri::from(&client_request_header.request);

    loop {
        match fetch(
            &uri,
            &cache_file_path,
            &client_request_header,
            &mut fetch_stream,
            &mut stream,
        )
        .await
        {
            Close => return Close,
            Keep => return Keep,
            Redirect(s) => {
                let new_uri = Uri::from(s);
                uri = uri.merge_with(&new_uri);
            }
            #[cfg(feature = "https")]
            Upgrade(_) => {}
        }
    }

    async fn fetch<R, S>(
        uri: &Uri<'_>,
        cache_file_path: &PathBuf,
        client_request_header: &HttpRequestHeader<'_>,
        fetch_stream: &mut R,
        mut stream: &mut S,
    ) -> ConnectionReturn
    where
        R: AsyncRead + AsyncWrite + Unpin,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let path_and_query = match uri.path_and_query {
            None => {
                let response = HttpResponseStatus::BAD_REQUEST.to_response();
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return Close;
                }
                return keep_alive_if(client_request_header);
            }
            Some(s) => s.to_string(),
        };

        let fetch_request = HttpRequestHeader {
            method: HttpRequestMethod::Get,
            request: Uri::from(path_and_query),
            version: HttpVersion::from(client_request_header.version.as_str()),
            headers: {
                let mut headers = client_request_header.headers.clone();
                headers.remove("Range"); /* Not cached so need to download from start */
                headers
            },
        };

        match fetch_request.generate() {
            None => {
                if stream
                    .write_all(
                        HttpResponseStatus::INTERNAL_SERVER_ERROR
                            .to_response()
                            .as_bytes(),
                    )
                    .await
                    .is_err()
                {
                    return Close;
                }
                return keep_alive_if(client_request_header);
            }
            Some(s) => {
                if fetch_stream.write_all(s.as_bytes()).await.is_err() {
                    if stream
                        .write_all(
                            HttpResponseStatus::INTERNAL_SERVER_ERROR
                                .to_response()
                                .as_bytes(),
                        )
                        .await
                        .is_err()
                    {
                        return Close;
                    }
                }
            }
        };

        let mut fetch_buf_reader = BufReader::new(fetch_stream);

        let mut fetch_response_header =
            match HttpResponseHeader::from_tcp_buffer_async(&mut fetch_buf_reader).await {
                None => {
                    eprintln!("Error: unable to extract header");
                    let response = HttpResponseStatus::BAD_GATEWAY.to_response();
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return Close;
                    }
                    return keep_alive_if(client_request_header);
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

        match fetch_response_header.status.to_code() {
            200 => {
                let cache_file_parent = match cache_file_path.parent() {
                    None => {
                        let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return Close;
                        }
                        return keep_alive_if(client_request_header);
                    }
                    Some(p) => p,
                };
                match create_dir_all(cache_file_parent).await {
                    Ok(_) => {}
                    Err(_) => {
                        let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return Close;
                        }
                    }
                }
                let mut file = match File::create(&cache_file_path).await {
                    Err(_) => {
                        let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return Close;
                        }
                        return keep_alive_if(client_request_header);
                    }
                    Ok(file) => file,
                };

                let (write_stream, write_file);

                if let Some(v) = fetch_response_header.headers.get("Transfer-Encoding") {
                    if v.to_lowercase() == "chunked" {
                        (write_stream, write_file) = fetch_and_serve_chunk(
                            cache_file_path,
                            &mut stream,
                            &mut fetch_buf_reader,
                            &mut file,
                        )
                        .await
                    } else {
                        let response = HttpResponseStatus::BAD_REQUEST.to_response();
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return Close;
                        }
                        return keep_alive_if(client_request_header);
                    }
                } else {
                    let content_length = match fetch_response_header.headers.get("Content-Length") {
                        None => {
                            let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                            if stream.write_all(response.as_bytes()).await.is_err() {
                                return Close;
                            }
                            return keep_alive_if(client_request_header);
                        }
                        Some(s) => match s.parse::<u64>() {
                            Ok(u) => u,
                            Err(_) => {
                                let response = HttpResponseStatus::BAD_REQUEST.to_response();
                                if stream.write_all(response.as_bytes()).await.is_err() {
                                    return Close;
                                }
                                return keep_alive_if(client_request_header);
                            }
                        },
                    };

                    (write_stream, write_file) = fetch_and_serve_known_length(
                        &cache_file_path,
                        &mut stream,
                        content_length,
                        &mut fetch_buf_reader,
                        &mut file,
                    )
                    .await;
                }

                let _ = timeout(Duration::from_millis(100), fetch_buf_reader.shutdown()).await;

                if write_stream {
                    let _ = timeout(Duration::from_millis(100), stream.shutdown()).await;
                }

                if write_file {
                    if let Some(last_modified) = fetch_response_header.headers.get("Last-Modified")
                    {
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
                keep_alive_if(client_request_header)
            }
            302 => {
                let url = match fetch_response_header.headers.get("Location") {
                    None => {
                        let response = HttpResponseStatus::BAD_REQUEST.to_response();
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return Close;
                        }
                        return keep_alive_if(client_request_header);
                    }
                    Some(s) => s,
                };
                Redirect(String::from(url))
            }
            _ => {
                let pass_through = fetch_response_header.generate();
                let _ = stream.write_all(pass_through.as_bytes()).await;
                keep_alive_if(client_request_header)
            }
        }
    }
}
