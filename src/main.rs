mod http;

use crate::http::{HttpRequestHeader, HttpRequestMethod, HttpResponseStatus};
use tokio::{
    fs,
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    let listener = match TcpListener::bind("127.0.0.1:7878").await {
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
    let buf_reader = BufReader::new(&mut stream);
    let header = match HttpRequestHeader::from_tcp_buffer_async(buf_reader).await {
        None => return,
        Some(header) => header,
    };

    match header.method {
        HttpRequestMethod::Get => {
            let response = match fs::read_to_string("hello.html").await {
                Ok(s) => {
                    let len = s.len();
                    let string = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n{s}");
                    string
                }

                Err(_) => HttpResponseStatus::NOT_FOUND.to_response(),
            };

            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default()
        }
        _ => {
            let response = HttpResponseStatus::METHOD_NOT_ALLOWED.to_response();
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_default()
        }
    }
}
