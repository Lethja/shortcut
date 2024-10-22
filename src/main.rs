mod http;

use crate::http::{HttpRequestHeader, HttpRequestMethod, HttpResponseStatus};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

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
    let buf_reader = BufReader::new(&mut stream);
    let header = match HttpRequestHeader::from_tcp_buffer_async(buf_reader).await {
        None => return,
        Some(header) => header,
    };

    #[cfg(debug_assertions)]
    println!("header = {:?}", header.generate());

    match header.method {
        HttpRequestMethod::Get => {
            if header.has_relative_path() {
                match header.get_query() {
                    None => {
                        let response = HttpResponseStatus::NO_CONTENT.to_header();
                        stream.write_all(response.as_bytes()).await.unwrap_or_else(|_| ());
                        return;
                    }
                    Some(_q) => {
                        todo!("If query is certs offer the certificate")
                    }
                };
            } else {

            }
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
