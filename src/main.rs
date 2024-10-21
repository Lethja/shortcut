use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
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
    let mut lines = buf_reader.lines();

    let mut http_request = Vec::new();
    while let Some(line) = lines.next_line().await.unwrap_or(None) {
        if line.is_empty() {
            break;
        }
        http_request.push(line);
    }

    let response = match fs::read_to_string("hello.html").await {
        Ok(s) => {
            let len = s.len();
            let string = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n{s}");
            string
        }

        Err(_) => {
            let error = "Content not found";
            let len = error.len();
            let string =
                format!("HTTP/1.1 404 FILE NOT FOUND\r\nContent-Length: {len}\r\n\r\n{error}");
            string
        }
    };

    stream.write_all(response.as_bytes()).await.unwrap();
}
