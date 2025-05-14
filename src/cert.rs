use {
    crate::{http::X_PROXY_CACHE_PATH, PKG_NAME},
    rcgen::{generate_simple_self_signed, CertifiedKey},
    rustls::{
        pki_types::pem::PemObject,
        pki_types::{CertificateDer, PrivateKeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    },
    rustls_native_certs::load_native_certs,
    std::{net::IpAddr, path::PathBuf, sync::Arc},
    tokio_rustls::{TlsAcceptor, TlsConnector},
};

pub const X_PROXY_TLS_PATH: &str = "X_PROXY_TLS_PATH";

pub const CERT_QUERY: &str = "?cert";

pub(crate) struct CertificateSetup {
    pub(crate) client_config: Arc<TlsConnector>,
    pub(crate) server_config: Arc<TlsAcceptor>,
    pub(crate) server_cert_path: PathBuf,
}

#[cfg(debug_assertions)]
/// **DO NOT USE THIS FUNCTION IN PRODUCTION**.
/// By bypassing all certificate checks, it exposes the connection to potential security risks,
/// including man-in-the-middle attacks.
/// This function should only be used
/// to simplify debugging of HTTPS connections during development.
fn treat_certificates_as_gospel() -> Arc<TlsConnector> {
    use {
        rustls::{
            client::danger::ServerCertVerifier,
            client::danger::{HandshakeSignatureValid, ServerCertVerified},
            pki_types::{ServerName, UnixTime},
            DigitallySignedStruct, Error, SignatureScheme,
        },
        std::fmt::{Debug, Formatter},
    };

    struct NoCertificateVerification;

    impl Debug for NoCertificateVerification {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            write!(f, "NoCertificateVerification")
        }
    }

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    eprintln!(
        "{PKG_NAME} will treat all HTTPS certificates as gospel for debugging purposes...\
        \n\nDO NOT USE THIS VERSION IN PRODUCTION!\n"
    );

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    // Create a ClientConfig with safe defaults and no client authentication
    let config = Arc::new(config);

    // Wrap the configuration in an Arc and return the TlsConnector
    Arc::new(TlsConnector::from(config))
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

#[allow(dead_code)]
fn create_dynamic_server_config(
    domain: &str,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};

    let proxy_cert = CertificateDer::from_pem_file(cert_path)?;
    let proxy_key = PrivateKeyDer::from_pem_file(key_path)?;

    // Create parameters for the new certificate
    let mut params = CertificateParams::new(vec![domain.to_string()])?;

    params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, domain);
        dn
    };

    let key_pair = KeyPair::generate()?;

    todo!("Sign key with proxy key/cert");

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![proxy_cert], proxy_key.clone_key())?;

    Ok(config)
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
        use {
            std::{
                ffi::OsStr, iter::once, os::windows::ffi::OsStrExt, process::exit, ptr::null_mut,
            },
            winapi::{
                ctypes::c_void,
                shared::winerror::ERROR_SUCCESS,
                um::{
                    accctrl::{
                        EXPLICIT_ACCESS_W, NO_INHERITANCE, SE_FILE_OBJECT, TRUSTEE_IS_SID,
                        TRUSTEE_IS_USER, TRUSTEE_W,
                    },
                    aclapi::{GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW},
                    winbase::LocalFree,
                    winnt::{
                        DACL_SECURITY_INFORMATION, DELETE, FILE_GENERIC_READ,
                        OWNER_SECURITY_INFORMATION, PACL, PROTECTED_DACL_SECURITY_INFORMATION,
                        PSECURITY_DESCRIPTOR, PSID,
                    },
                },
            },
        };

        let path: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let mut p_owner_sid: PSID = null_mut();
        let mut p_sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut p_new_dacl: PACL = null_mut();

        let cleanup = move || unsafe {
            if !&p_sd.is_null() {
                LocalFree(p_sd as *mut c_void);
            }
            if !&p_new_dacl.is_null() {
                LocalFree(p_new_dacl as *mut c_void);
            }
        };

        let result = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut p_owner_sid,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut p_sd,
            )
        };

        if result != ERROR_SUCCESS {
            cleanup();
            eprintln!("Failed to set owner permissions: {}", result);
            exit(1);
        }

        let mut ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ | DELETE,
            grfAccessMode: winapi::um::accctrl::SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: winapi::um::accctrl::NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: p_owner_sid as *mut _,
            },
        };

        let result = unsafe { SetEntriesInAclW(1, &mut ea, null_mut(), &mut p_new_dacl) };

        if result != ERROR_SUCCESS {
            cleanup();
            eprintln!("Failed to set owner permissions: {}", result);
            exit(1);
        }

        let result = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                p_new_dacl,
                null_mut(),
            )
        };

        if result != ERROR_SUCCESS {
            cleanup();
            eprintln!("Failed to set ACL: {}", result);
            exit(1);
        }

        cleanup();
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

    // Get interfaces and their IPs
    let interfaces = get_if_addrs::get_if_addrs().unwrap();

    for interface in interfaces {
        let address = interface.addr;
        // Check if it's an IPv4 address
        if let IpAddr::V4(ipv4_addr) = address.ip() {
            if ipv4_addr.is_private() {
                subject_alt_names.push(ipv4_addr.to_string());
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
    #[cfg(debug_assertions)]
    let client_config = match std::env::var("X_PROXY_CERT_GOSPEL") {
        Ok(_) => treat_certificates_as_gospel(),
        Err(_) => load_system_certificates(),
    };

    #[cfg(not(debug_assertions))]
    let client_config = load_system_certificates();
    let (server_cert_path, server_key_path) = check_or_create_tls();
    let server_config = load_server_certificates(&server_cert_path, &server_key_path);

    CertificateSetup {
        client_config,
        server_config,
        server_cert_path,
    }
}
