use http::{Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http1::{Builder, SendRequest},
    upgrade::Upgraded,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

pub fn react_bad_request() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let mut resp = Response::new(empty());
    *resp.status_mut() = StatusCode::BAD_REQUEST;

    return Ok(resp);
}

pub fn react_bad_request_msg(
    message: Bytes,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let mut resp = Response::new(full(message));
    *resp.status_mut() = StatusCode::BAD_REQUEST;

    return Ok(resp);
}

pub async fn meta_lookup(
    res: Request<Incoming>,
    mut sender: SendRequest<Incoming>,
) -> Result<Response<Incoming>, hyper::Error> {
    let mut req = res;
    /* Determine if cached data is stale, convert request method to HEAD */
    *req.method_mut() = Method::HEAD;
    /* TODO: Make the uri relative before sending (not all servers act well to absolute addresses) */
    /* TODO: Check if the file is already on the disk, serve it directly if it's not stale or check against metadata if it is*/
    let res = sender.send_request(req).await;
    /* TODO: Unwrap and compare head data to that in a local database to decide what do to next */
    res /* TODO: temporary return, this function should end the HEAD stage with a conclusion on what the caller has to do next */
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
