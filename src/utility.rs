use http::Response;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http1::{Builder, SendRequest},
    upgrade::Upgraded,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

pub fn cache(
    res: Response<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    /* TODO: Handle reading the file */
    /* TODO: Handle writing the file */
    Ok(res.map(|b| b.boxed()))
}

pub fn default_port(scheme: &str) -> u16 {
    match scheme {
        "HTTPS" => 443,
        _ => 80,
    }
}

pub fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

//Build a send request
pub async fn build_sender(host: &str, port: u16) -> Result<SendRequest<Incoming>, hyper::Error> {
    let stream = TcpStream::connect((host, port)).await.unwrap();
    let io = TokioIo::new(stream);

    let (sender, conn) = Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    Ok(sender)
}

// Handle HTTPS requests (we can't cache these)
pub async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}
