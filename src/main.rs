mod http;

use crate::http::{HttpRequestHeader, HttpRequestMethod, HttpResponseHeader, HttpResponseStatus};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    join,
    net::{TcpListener, TcpStream},
};
use url::{Host, Url};

#[tokio::main]
async fn main() {
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

    #[cfg(debug_assertions)]
    println!("header = {:?}", client_request_header.generate());

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

            let mut fetch_stream = match TcpStream::connect(host).await {
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
                    headers.remove("Range");
                    headers
                },
            };

            match fetch_buf_reader
                .write_all(fetch_request.generate().as_ref())
                .await
            {
                Ok(_) => {}
                Err(_) => {
                    let response = HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                    client_buf_reader
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
            match client_buf_reader
                .write_all(fetch_response_header_data.as_bytes())
                .await
            {
                Ok(_) => {}
                Err(_) => return,
            }

            if fetch_response_header.status.to_code() == 200 {
                let path = match fetch_response_header
                    .get_cache_name(&client_request_header.path)
                {
                    None => {
                        let response =
                            HttpResponseStatus::INTERNAL_SERVER_ERROR.to_response();
                        client_buf_reader
                            .write_all(response.as_bytes())
                            .await
                            .unwrap_or_default();
                        return;
                    }
                    Some(p) => p,
                };
                let mut file = match File::create(path).await {
                    Err(_) => return,
                    Ok(file) => file,
                };

                let mut buffer = vec![0; 8192]; // Adjust buffer size as needed

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
                            let client_write_future = client_buf_reader.write_all(data);

                            let _ =  join!(file_write_future, client_write_future);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn url_is_http(url: &Url) -> Option<Host> {
    if url.scheme() != "http" {
        return None;
    }

    let host = match url.host() {
        None => return None,
        Some(s) => s,
    };

    let port = url.port_or_known_default().unwrap_or(80);

    let host = format!("{host}:{port}");

    match Host::parse(host.as_str()) {
        Ok(h) => Some(h),
        Err(_) => None,
    }
}
