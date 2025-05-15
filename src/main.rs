#[cfg(feature = "https")]
mod cert;
mod conn;
mod debug;
mod fetch;
mod http;
mod serve;

#[cfg(feature = "https")]
use {
    crate::{
        cert::{setup_certificates, CertificateSetup},
        conn::{Uri, UriKind::*},
        http::{respond_with, ConnectionReturn, ConnectionReturn::Upgrade, HttpResponseStatus},
    },
    tokio::net::TcpStream,
};

use {
    crate::{
        conn::Flights,
        http::{ConnectionReturn::Keep, X_PROXY_CACHE_PATH, X_PROXY_ROOT_PATH},
        serve::{read_http_request, serve_http_request},
    },
    std::{path::PathBuf, sync::Arc},
    tokio::{net::TcpListener, sync::Semaphore},
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
                eprintln!(
                    "{PKG_NAME} {X_PROXY_CACHE_PATH} ({}) is not a directory",
                    path.to_str().unwrap_or("?")
                );
                return;
            }
            eprintln!("{PKG_NAME} cache path: {s}");
        }
        Err(_) => match std::env::var(X_PROXY_ROOT_PATH) {
            Ok(s) => {
                let path = PathBuf::from(&s).join("cache");
                match std::fs::create_dir(&path) {
                    Ok(_) => {
                        eprintln!(
                            "{PKG_NAME} new cache path: {}",
                            &path.to_str().unwrap_or("?")
                        );
                    }
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::AlreadyExists => {
                            eprintln!("{PKG_NAME} cache path: {}", &path.to_str().unwrap_or("?"));
                        }
                        _ => {
                            eprintln!(
                                "Error: couldn't create directory '{}': {e}",
                                &path.to_str().unwrap_or("?")
                            );
                            std::process::exit(1);
                        }
                    },
                }
                std::env::set_var(X_PROXY_CACHE_PATH, &path);
            }
            Err(_) => {
                eprintln!("Error: '{X_PROXY_ROOT_PATH}' or '{X_PROXY_CACHE_PATH}' has to be set to a directory to continue");
                return;
            }
        },
    };

    #[cfg(feature = "https")]
    let certificates = Arc::new(setup_certificates());

    let flight_plan = Arc::new(Flights::new());

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
            &flight_plan,
            &semaphore,
            #[cfg(feature = "https")]
            &certificates,
        )
        .await;
    }
}

async fn listen_for(
    http_listener: &TcpListener,
    flights: &Arc<Flights>,
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
    let flights = Arc::clone(flights);

    tokio::spawn(async move {
        match semaphore.acquire().await {
            Ok(_) => {}
            Err(_) => return,
        };

        loop {
            let client_request = match read_http_request(&mut stream).await {
                None => return,
                Some(x) => x,
            };

            match serve_http_request(
                &mut stream,
                &flights,
                client_request,
                #[cfg(feature = "https")]
                &certificates,
            )
            .await
            {
                #[cfg(feature = "https")]
                Upgrade(h) => listen_for_https(h, &mut stream, &flights, &certificates).await,
                Keep => continue,
                _ => return,
            }
        }
    });
}

#[cfg(feature = "https")]
async fn listen_for_https(
    mut host: String,
    stream: &mut TcpStream,
    flights: &Arc<Flights>,
    certificates: &Arc<CertificateSetup>,
) {
    if respond_with(Keep, HttpResponseStatus::OK, stream).await == ConnectionReturn::Close {
        return;
    };

    use {rustls::server::Acceptor, tokio_rustls::LazyConfigAcceptor};

    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
    tokio::pin!(acceptor);

    let (mut stream, sni) = match acceptor.as_mut().await {
        Ok(start) => {
            let sni = start.client_hello().server_name().map(|x| x.to_string());

            match sni {
                Some(sni) => {
                    // TODO: replace with dynamic certificate based on sni.
                    match start
                        .into_stream(certificates.server_config.config().clone())
                        .await
                    {
                        Ok(stream) => (stream, Some(sni)),
                        Err(e) => {
                            eprintln!("{PKG_NAME} couldn't create tls stream: {e}");
                            return;
                        }
                    }
                }
                None => {
                    match start
                        .into_stream(certificates.server_config.config().clone())
                        .await
                    {
                        Ok(stream) => (stream, None),
                        Err(e) => {
                            eprintln!("{PKG_NAME} couldn't create tls stream: {e}");
                            return;
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("{PKG_NAME} couldn't create tls stream: {e}");
            return;
        }
    };

    if let Some(sni) = sni {
        if host != sni {
            eprintln!("{PKG_NAME} aborted https request: SNI ({sni}) mismatched request ({host})");
            return; // TODO: add a HTTP error about SNI differing from host
        }
    }

    host.insert_str(0, "https://");
    debug_print!("Connect request to {} is being established", host);

    let host = Uri::from(host);
    if host.kind() != Host {
        return;
    }

    loop {
        let mut client_request = match read_http_request(&mut stream).await {
            None => return,
            Some(x) => x,
        };

        if client_request.request.kind() != ResolvedAddress {
            client_request.request = client_request.request.merge_with(&host);
        }

        match serve_http_request(&mut stream, flights, client_request, certificates).await {
            Keep => continue,
            _ => return,
        }
    }
}
