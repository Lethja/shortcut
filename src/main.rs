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
        conn::{
            Uri,
            UriKind::{AbsoluteAddress, Host},
        },
        http::{respond_with, ConnectionReturn, ConnectionReturn::Upgrade, HttpResponseStatus},
    },
    tokio::net::TcpStream,
};

use {
    crate::{
        http::{ConnectionReturn::Keep, X_PROXY_CACHE_PATH},
        serve::{read_http_request, serve_http_request},
    },
    std::{path::PathBuf, sync::Arc},
    tokio::{fs::create_dir_all, net::TcpListener, sync::Semaphore},
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
        let _ = match semaphore.acquire().await {
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
                client_request,
                #[cfg(feature = "https")]
                &*certificates,
            )
            .await
            {
                #[cfg(feature = "https")]
                Upgrade(h) => listen_for_https(h, &mut stream, &certificates).await,
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
    certificates: &Arc<CertificateSetup>,
) {
    if respond_with(Keep, HttpResponseStatus::OK, stream).await == ConnectionReturn::Close {
        return;
    };

    let acceptor = certificates.server_config.clone();

    let mut stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{PKG_NAME} couldn't create tls stream: {e}");
            return;
        }
    };

    host.insert_str(0, "https://");
    let host = Uri::from(host);

    if host.kind() != Host {
        return;
    }

    loop {
        let mut client_request = match read_http_request(&mut stream).await {
            None => return,
            Some(x) => x,
        };

        if client_request.request.kind() != AbsoluteAddress {
            client_request.request = client_request.request.merge_with(&host);
        }

        match serve_http_request(&mut stream, client_request, &*certificates).await {
            Keep => continue,
            _ => return,
        }
    }
}
