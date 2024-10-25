mod http;

use crate::http::{
    get_cache_name, url_is_http, HttpRequestHeader, HttpRequestMethod, HttpResponseHeader,
    HttpResponseStatus, HttpVersion, BUFFER_SIZE,
};
use std::{collections::HashMap, path::PathBuf};
use tokio::{
    fs::{create_dir_all, File},
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    join,
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    match std::env::var("X_CACHE_PROXY_PATH") {
        Ok(s) => {
            let path = PathBuf::from(&s);
            if !path.exists() {
                if let Err(e) = create_dir_all(&path).await {
                    eprintln!("Failed to create directory: {e}");
                    return;
                }
            }
            drop(s)
        }
        Err(_) => {
            eprintln!("\"X_CACHE_PROXY_PATH\" has not been set");
            return;
        }
    };

    let listener = match TcpListener::bind("0.0.0.0:3142").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Unable to bind server: {e}");
            return;
        }
    };

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Unable to accept server socket: {e}");
                return;
            }
        };

        tokio::spawn(async move {
            handle_connection(stream).await;
        });
    }
}

async fn handle_connection(mut stream: TcpStream) {
    let mut client_buf_reader = BufReader::new(&mut stream);
    let client_request_header =
        match HttpRequestHeader::from_tcp_buffer_async(&mut client_buf_reader).await {
            None => return,
            Some(header) => header,
        };

    if let HttpRequestMethod::Get = client_request_header.method {
        if client_request_header.has_relative_path() {
            match client_request_header.get_query() {
                None => {
                    let response = HttpResponseStatus::NO_CONTENT.to_header();
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_default();
                }
                Some(_q) => {
                    todo!("If query is certs offer the certificate")
                }
            };
        } else {
            let host = match url_is_http(&client_request_header.path) {
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

            let cache_file_path = match get_cache_name(&client_request_header.path).await {
                None => return,
                Some(p) => p,
            };

            if cache_file_path.exists() {
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

                let mut headers = HashMap::<String, String>::new();
                headers.insert(String::from("Content-Length"), metadata.len().to_string());

                let mut header = HttpResponseHeader {
                    status: HttpResponseStatus::OK,
                    headers,
                    version: HttpVersion::HTTP_V11,
                };

                let header = header.generate();
                let _ = stream.write_all(header.as_ref()).await;
                let mut buffer = vec![0; BUFFER_SIZE];

                loop {
                    match file.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            } else {
                let mut fetch_stream = match TcpStream::connect(&host).await {
                    Ok(s) => s,
                    Err(_) => {
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
                    path: client_request_header.path.clone(),
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
                    let mut file = match File::create(cache_file_path).await {
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

                    let mut buffer = vec![0; BUFFER_SIZE]; // Adjust buffer size as needed

                    loop {
                        match fetch_buf_reader.read(&mut buffer).await {
                            Ok(0) => {
                                // Connection closed
                                break;
                            }
                            Ok(n) => {
                                // Process received binary data
                                let data = &buffer[..n];

                                let file_write_future = file.write_all(data);
                                let client_write_future = stream.write_all(data);

                                let _ = join!(file_write_future, client_write_future);
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
