use crate::http::X_PROXY_CACHE_PATH;
use pnet::datalink;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::{net::IpAddr, path::PathBuf};

pub const X_PROXY_TLS_PATH: &str = "X_PROXY_TLS_PATH";

pub const CERT_QUERY: &str = "?cert";

pub(crate) fn check_or_create_tls() -> (PathBuf, PathBuf) {
    fn set_read_only(path: &PathBuf) {
        match std::fs::metadata(path) {
            Ok(m) => {
                let mut perms = m.permissions();

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    perms.set_mode(0o600);
                }

                #[cfg(windows)]
                {
                    use std::os::windows::fs::PermissionsExt;
                    perms.set_readonly(true);
                }

                let _ = std::fs::set_permissions(path, perms);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    let path = match std::env::var(X_PROXY_TLS_PATH) {
        Ok(p) => {
            let path = PathBuf::from(&p);
            if !path.is_dir() {
                eprintln!("X_PROXY_TLS_PATH ({}) should be set to a directory", p);
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
            "rproxy using existing key and certificate in '{}'",
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
        "rproxy generated key and self-signed certificate in '{}'. \
        This certificate can be downloaded from the servers '/{}' path",
        String::from(path.to_str().unwrap()),
        CERT_QUERY
    );

    (cert_path, key_path)
}
