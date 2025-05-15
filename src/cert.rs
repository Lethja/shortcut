use {
    crate::{http::X_PROXY_ROOT_PATH, PKG_NAME},
    rcgen::CertifiedKey,
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    },
    rustls_native_certs::load_native_certs,
    std::{path::PathBuf, sync::Arc},
    tokio_rustls::{TlsAcceptor, TlsConnector},
};

pub const X_PROXY_HTTPS_PATH: &str = "X_PROXY_HTTPS_PATH";

pub const CERT_QUERY: &str = "?cert";

pub(crate) struct CertificateSetup {
    pub(crate) client_config: Arc<TlsConnector>,
    pub(crate) server_config: Arc<TlsAcceptor>,
    pub(crate) server_cert_path: PathBuf,
    pub(crate) cert_path: PathBuf,
    pub(crate) certificate: CertifiedKey,
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
    certificate_setup: &CertificateSetup,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};

    todo!("Refactor to use 'certificate' and 'cert_path' members");

    /*
    let proxy_cert = CertificateDer::from_pem_file(cert_path)?;
    let proxy_key = PrivateKeyDer::from_pem_file(key_path)?;
     */

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

    /*
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![proxy_cert], proxy_key.clone_key())?;

    Ok(config)
     */
}

fn load_server_certificates(cert: &CertifiedKey) -> Arc<TlsAcceptor> {
    use rustls::pki_types::PrivatePkcs8KeyDer;

    let config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
        ) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{PKG_NAME} unable to create server https config: {e}");
            std::process::exit(1);
        }
    };

    let config = Arc::new(config);

    Arc::new(TlsAcceptor::from(config))
}

fn check_or_create_tls() -> (CertifiedKey, PathBuf, PathBuf) {
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

    let path = match std::env::var(X_PROXY_HTTPS_PATH) {
        Ok(p) => {
            let path = PathBuf::from(&p);
            if !path.is_dir() {
                eprintln!("{PKG_NAME} {X_PROXY_HTTPS_PATH} ({}) is not a directory", p);
                std::process::exit(1);
            }
            path
        }
        Err(_) => match std::env::var(X_PROXY_ROOT_PATH) {
            Ok(p) => {
                let path = PathBuf::from(p).join("https");
                match std::fs::create_dir(&path) {
                    Ok(_) => {}
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::AlreadyExists => {}
                        _ => {
                            eprintln!(
                                "Error: couldn't create directory '{}': {e}",
                                &path.to_str().unwrap_or("?")
                            );
                            std::process::exit(1);
                        }
                    },
                };
                std::env::set_var(X_PROXY_HTTPS_PATH, &path);
                path
            }
            Err(e) => {
                eprintln!("Error: '{X_PROXY_ROOT_PATH}' or '{X_PROXY_HTTPS_PATH}' has to be set to a directory to continue");
                std::process::exit(1);
            }
        },
    };

    let cert_path = path.join("cert.pem");
    let key_path = path.join("priv.key");

    use rcgen::{CertificateParams, KeyPair};

    if cert_path.exists() && key_path.exists() {
        eprintln!("{PKG_NAME} https path '{}'", path.to_str().unwrap_or("?"));

        let param = match std::fs::read_to_string(&cert_path) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        let param = match CertificateParams::from_ca_cert_pem(param.as_str()) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        let key_pair = match std::fs::read_to_string(&key_path) {
            Ok(x) => x.to_string(),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        let key_pair = match KeyPair::from_pem(key_pair.as_str()) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        let cert = param.self_signed(&key_pair).unwrap();

        return (CertifiedKey { cert, key_pair }, path, cert_path);
    }

    let mut param = CertificateParams::default();

    param.distinguished_name = rcgen::DistinguishedName::new();
    param.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("shortcut-proxy".to_string()),
    );
    param.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key_pair = KeyPair::generate().unwrap();
    let cert = param.self_signed(&key_pair).unwrap();

    let root_key = CertifiedKey { cert, key_pair };

    match std::fs::write(&cert_path, root_key.cert.pem()) {
        Ok(_) => {
            set_read_only(&cert_path);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }

    match std::fs::write(&key_path, root_key.key_pair.serialize_pem()) {
        Ok(_) => {
            set_read_only(&key_path);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }

    eprintln!("{PKG_NAME} new https path '{}'. The new self-signed certificate can be downloaded from the servers '/{}' path", path.to_str().unwrap_or("?"), CERT_QUERY);

    (root_key, path, cert_path)
}

pub(crate) fn setup_certificates() -> CertificateSetup {
    let (certificate, cert_path, server_cert_path) = check_or_create_tls();

    #[cfg(debug_assertions)]
    let client_config = match std::env::var("X_PROXY_CERT_GOSPEL") {
        Ok(_) => treat_certificates_as_gospel(),
        Err(_) => load_system_certificates(),
    };

    #[cfg(not(debug_assertions))]
    let client_config = load_system_certificates();

    let server_config = load_server_certificates(&certificate);

    CertificateSetup {
        client_config,
        server_config,
        server_cert_path,
        cert_path,
        certificate,
    }
}
