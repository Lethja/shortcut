use {
    crate::{
        conn,
        conn::{FlightState, Flights},
        fetch::fetch_and_serve_file,
        http::{
            get_cache_name, keep_alive_if, respond_with, ConnectionReturn, ConnectionReturn::Close,
            HttpRequestHeader, HttpRequestMethod, HttpResponseHeader, HttpResponseStatus,
            HttpVersion, BUFFER_SIZE,
        },
    },
    std::{collections::HashMap, io::SeekFrom, path::PathBuf, sync::Arc, time::Duration},
    tokio::{
        fs::File,
        io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader},
        time::timeout,
    },
};

#[cfg(feature = "https")]
use {
    crate::cert::{CertificateSetup, CERT_QUERY},
    ConnectionReturn::Upgrade,
};

pub(crate) async fn read_http_request<T>(mut stream: T) -> Option<HttpRequestHeader<'static>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf_reader = BufReader::new(&mut stream);

    match timeout(
        Duration::from_secs(5),
        HttpRequestHeader::from_tcp_buffer_async(&mut client_buf_reader),
    )
    .await
    {
        Ok(c) => match c {
            None => None,
            Some(header) => Some(header),
        },
        Err(_) => None,
    }
}

pub(crate) async fn serve_http_request<T>(
    mut stream: T,
    flights: &Arc<Flights>,
    client_request_header: HttpRequestHeader<'_>,
    #[cfg(feature = "https")] cert: &CertificateSetup,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
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
                                    &mut stream,
                                    flights,
                                    &client_request_header,
                                )
                                .await;
                            } else {
                                return respond_with(
                                    keep_alive_if(&client_request_header),
                                    HttpResponseStatus::NOT_FOUND,
                                    &mut stream,
                                )
                                .await;
                            }
                        }
                    }
                    _ => {
                        return respond_with(
                            keep_alive_if(&client_request_header),
                            HttpResponseStatus::NO_CONTENT,
                            &mut stream,
                        )
                        .await
                    }
                }
                #[cfg(feature = "https")]
                respond_with(
                    keep_alive_if(&client_request_header),
                    HttpResponseStatus::INTERNAL_SERVER_ERROR,
                    &mut stream,
                )
                .await
            }
            _ => {
                let (cache_file_path, hash) = match get_cache_name(&client_request_header).await {
                    None => {
                        return respond_with(
                            keep_alive_if(&client_request_header),
                            HttpResponseStatus::INTERNAL_SERVER_ERROR,
                            &mut stream,
                        )
                        .await
                    }
                    Some(p) => {
                        let hash = p.to_string_lossy().to_string();
                        (p, hash)
                    }
                };

                if cache_file_path.exists() || flights.is_in_flight(&hash).await {
                    serve_existing_file(&cache_file_path, stream, flights, &client_request_header)
                        .await
                } else {
                    flights.takeoff(&hash, FlightState::Fetching).await;

                    let r = fetch_and_serve_file(
                        cache_file_path,
                        stream,
                        flights,
                        client_request_header,
                        #[cfg(feature = "https")]
                        cert,
                    )
                    .await;

                    flights.land(&hash).await;
                    r
                }
            }
        },
        #[cfg(feature = "https")]
        HttpRequestMethod::Connect => {
            match (
                client_request_header.request.host,
                client_request_header.request.port,
            ) {
                (Some(_), Some(_)) => Upgrade(client_request_header.request.uri),
                _ => {
                    respond_with(
                        Close,
                        HttpResponseStatus::INTERNAL_SERVER_ERROR,
                        &mut stream,
                    )
                    .await
                }
            }
        }
        _ => {
            respond_with(
                keep_alive_if(&client_request_header),
                HttpResponseStatus::METHOD_NOT_ALLOWED,
                &mut stream,
            )
            .await
        }
    }
}

async fn serve_in_flight_file_chunks<T>(
    mut cache_file: File,
    cache_file_path: &PathBuf,
    mut stream: T,
    flights: &Arc<Flights>,
    client_request_header: &HttpRequestHeader<'_>,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /* TODO: Chunk encoded flight */
    Close
}

async fn serve_in_flight_file_length<T>(
    mut cache_file: File,
    cache_file_path: &PathBuf,
    mut stream: T,
    flights: &Arc<Flights>,
    client_request_header: &HttpRequestHeader<'_>,
    total_length: u64,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let status = HttpResponseStatus::OK;
    let mut headers = HashMap::<String, String>::new();
    headers.insert(String::from("Content-Length"), total_length.to_string());

    let mut header = HttpResponseHeader {
        status,
        headers,
        version: HttpVersion::HTTP_V11,
    };

    let header = header.generate();
    if stream.write_all(header.as_bytes()).await.is_err() {
        return Close;
    }

    let mut current_position = 0;
    let mut buffer = vec![0; BUFFER_SIZE];

    loop {
        if current_position >= total_length {
            break; /* The transfer is finished */
        }

        match cache_file.read(&mut buffer).await {
            Ok(0) => {
                /* No new data available, at the moment */
                if !flights
                    .is_in_flight(&cache_file_path.to_string_lossy().to_string())
                    .await
                {
                    return Close; /* The flight is gone, no other choice but to abort */
                }

                /* Wait a while before retrying */
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(n) => {
                if stream.write_all(&buffer[..n]).await.is_err() {
                    return Close;
                }
                current_position += n as u64;

                if n < BUFFER_SIZE {
                    /* Wait a little while to allow warrant enough bytes to send another packet */
                    tokio::time::sleep(Duration::from_millis(30)).await; /* Nagle's algorithm */
                }
            }
            Err(_) => return Close,
        }
    }

    keep_alive_if(client_request_header)
}

async fn serve_in_flight_file<T>(
    cache_file: File,
    cache_file_path: &PathBuf,
    stream: T,
    flights: &Arc<Flights>,
    client_request_header: &HttpRequestHeader<'_>,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match flights
            .flight_state(&cache_file_path.to_string_lossy().to_string())
            .await
        {
            None => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Some(f) => match f {
                FlightState::Fetching => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                FlightState::Length(l) => {
                    return serve_in_flight_file_length(
                        cache_file,
                        cache_file_path,
                        stream,
                        flights,
                        client_request_header,
                        l,
                    )
                    .await
                }
                FlightState::Chunks => {
                    return serve_in_flight_file_chunks(
                        cache_file,
                        cache_file_path,
                        stream,
                        flights,
                        client_request_header,
                    )
                    .await
                }
            },
        }
    }
}

async fn serve_existing_file<T>(
    cache_file_path: &PathBuf,
    mut stream: T,
    flights: &Arc<Flights>,
    client_request_header: &HttpRequestHeader<'_>,
) -> ConnectionReturn
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = match File::open(cache_file_path).await {
        Ok(f) => f,
        Err(_) => {
            return respond_with(
                keep_alive_if(&client_request_header),
                HttpResponseStatus::INTERNAL_SERVER_ERROR,
                &mut stream,
            )
            .await
        }
    };

    if flights
        .is_in_flight(&cache_file_path.to_string_lossy().to_string())
        .await
    {
        return serve_in_flight_file(
            file,
            cache_file_path,
            stream,
            flights,
            client_request_header,
        )
        .await;
    }

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => {
            return respond_with(
                keep_alive_if(&client_request_header),
                HttpResponseStatus::INTERNAL_SERVER_ERROR,
                &mut stream,
            )
            .await
        }
    };

    let length = metadata.len();
    if length == 0 {
        return respond_with(
            keep_alive_if(&client_request_header),
            HttpResponseStatus::NO_CONTENT,
            &mut stream,
        )
        .await;
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
        return respond_with(
            keep_alive_if(&client_request_header),
            HttpResponseStatus::BAD_REQUEST,
            &mut stream,
        )
        .await;
    }

    let mut bytes: u64 = end_position - start_position + 1;

    while bytes > 0 {
        let bytes_to_read = std::cmp::min(BUFFER_SIZE as u64, bytes) as usize;
        match file.read(&mut buffer[..bytes_to_read]).await {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buffer[..n]).await.is_err() {
                    return Close; /* Something went wrong mid-transmission */
                }
                bytes -= n as u64;
            }
            Err(_) => break,
        }
    }
    keep_alive_if(client_request_header) /* Existing file transfer finished */
}
