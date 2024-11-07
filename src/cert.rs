use crate::{http::X_PROXY_CACHE_PATH, PKG_NAME};
use pnet::datalink;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    pki_types::pem::PemObject,
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_native_certs::load_native_certs;
use std::{net::IpAddr, path::PathBuf, sync::Arc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const X_PROXY_TLS_PATH: &str = "X_PROXY_TLS_PATH";

pub const CERT_QUERY: &str = "?cert";

pub(crate) struct CertificateSetup {
    #[allow(dead_code)] pub(crate) client_config: Arc<TlsConnector>,
    pub(crate) server_config: Arc<TlsAcceptor>,
    pub(crate) server_cert_path: PathBuf,
}

fn load_system_certificates() -> Arc<TlsConnector> {
    let mut root_store = RootCertStore::empty();
    let certs = load_native_certs();

    for error in certs.errors {
        eprintln!("{PKG_NAME} couldn't load a system certificate: {}", error);
    }

    for cert in certs.certs {
        let _ = root_store.add(cert);
    }

    if root_store.is_empty() {
        eprintln!("{PKG_NAME} couldn't load any system certificates");
        std::process::exit(1);
    }
    eprintln!("{PKG_NAME} loaded {} system certificates", root_store.len());
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    Arc::new(TlsConnector::from(config))
}

fn load_server_certificates(cert_path: &PathBuf, key_path: &PathBuf) -> Arc<TlsAcceptor> {
    let cert = match CertificateDer::from_pem_file(cert_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{PKG_NAME} error loading '{}': {}",
                cert_path.to_str().unwrap_or("?"),
                e
            );
            std::process::exit(1);
        }
    };

    let key = match PrivateKeyDer::from_pem_file(key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "{PKG_NAME} error loading '{}': {}",
                key_path.to_str().unwrap_or("?"),
                e
            );
            std::process::exit(1);
        }
    };

    let config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
    {
        Ok(c) => {
            eprintln!(
                "{PKG_NAME} using server https cert '{}' and key '{}'",
                cert_path.to_str().unwrap_or("?"),
                key_path.to_str().unwrap_or("?")
            );
            c
        }
        Err(e) => {
            eprintln!("{PKG_NAME} unable to create server https config: {e}");
            std::process::exit(1);
        }
    };

    let config = Arc::new(config);

    Arc::new(TlsAcceptor::from(config))
}

fn check_or_create_tls() -> (PathBuf, PathBuf) {
    #[cfg(unix)]
    fn set_read_only(path: &PathBuf) {
        match std::fs::metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().set_mode(0o400);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    #[cfg(windows)]
    fn set_read_only(path: &PathBuf) {
        todo!("Windows file permission nonsense")
    }

    let path = match std::env::var(X_PROXY_TLS_PATH) {
        Ok(p) => {
            let path = PathBuf::from(&p);
            if !path.is_dir() {
                eprintln!(
                    "{PKG_NAME} X_PROXY_TLS_PATH ({}) should be set to a directory",
                    p
                );
                std::process::exit(1);
            }
            path
        }
        Err(_) => {
            let p = match std::env::var(X_PROXY_CACHE_PATH) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            PathBuf::from(p)
        }
    };

    let cert_path = path.join("cert.pem");
    let key_path = path.join("priv.key");

    if cert_path.exists() && key_path.exists() {
        eprintln!(
            "{PKG_NAME} using existing key and certificate in '{}'",
            path.to_str().unwrap()
        );
        return (cert_path, key_path);
    }

    let mut subject_alt_names = Vec::<String>::new();

    subject_alt_names.push("*.local".to_string());

    let interfaces = datalink::interfaces();

    for interface in interfaces {
        for ip in interface.ips {
            if let IpAddr::V4(ipv4_addr) = ip.ip() {
                if ipv4_addr.is_private() {
                    subject_alt_names.push(ipv4_addr.to_string());
                }
            }
        }
    }

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(subject_alt_names.to_vec()).unwrap();

    match std::fs::write(&cert_path, cert.pem()) {
        Ok(_) => {
            set_read_only(&cert_path);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }

    match std::fs::write(&key_path, key_pair.serialize_pem()) {
        Ok(_) => {
            set_read_only(&key_path);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }

    eprintln!(
        "{PKG_NAME} generated key and self-signed certificate in '{}'. \
        This certificate can be downloaded from the servers '/{}' path",
        String::from(path.to_str().unwrap()),
        CERT_QUERY
    );

    (cert_path, key_path)
}

pub(crate) fn setup_certificates() -> CertificateSetup {
    let client_config = load_system_certificates();
    let (server_cert_path, server_key_path) = check_or_create_tls();
    let server_config = load_server_certificates(&server_cert_path, &server_key_path);

    CertificateSetup {
        client_config,
        server_config,
        server_cert_path,
    }
}
