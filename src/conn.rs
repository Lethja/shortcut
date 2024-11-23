use std::{fmt, pin::Pin};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::conn::{FetchRequestError::*, StreamType::*};

#[cfg(feature = "https")]
use {std::convert::TryFrom, tokio_rustls::client};

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct Uri<'a> {
    pub(crate) uri: String,
    pub(crate) scheme: Option<&'a str>,
    pub(crate) host: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) path: Option<&'a str>,
    pub(crate) query: Option<&'a str>,
    pub(crate) path_and_query: Option<&'a str>,
}

impl PartialEq for Uri<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.uri == other.uri
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum UriKind {
    AbsoluteAddress,
    AbsolutePath,
    Host,
    RelativeAddress,
    ResolvedAddress,
    Invalid,
}

impl<'a> From<String> for Uri<'a> {
    fn from(uri: String) -> Self {
        Uri::new(uri)
    }
}

impl<'a> From<&String> for Uri<'a> {
    fn from(uri: &String) -> Self {
        Uri::new(uri.clone())
    }
}

impl<'a> From<&Uri<'_>> for Uri<'a> {
    fn from(uri: &Uri) -> Self {
        Uri::new(uri.uri.clone())
    }
}

impl<'a> Uri<'a> {
    pub(crate) fn new(uri: String) -> Uri<'a> {
        let mut uri = Uri {
            uri,
            scheme: None,
            host: None,
            port: None,
            path: None,
            query: None,
            path_and_query: None,
        };

        let uri_ref: *mut Uri<'a> = &mut uri;
        unsafe {
            (*uri_ref).update_references();
        }
        uri
    }

    pub(crate) fn kind(&self) -> UriKind {
        match (self.scheme, self.host, self.port, self.path) {
            (Some(_), Some(_), Some(_), Some(_)) => UriKind::ResolvedAddress,
            (_, Some(_), Some(_), Some(_)) => UriKind::AbsoluteAddress,
            (_, Some(_), Some(_), _) => UriKind::Host,
            (_, Some(_), _, Some(_)) => UriKind::RelativeAddress,
            (_, _, _, Some(path)) => {
                if path.starts_with('/') {
                    UriKind::AbsolutePath
                } else {
                    UriKind::Invalid
                }
            }
            _ => UriKind::Invalid,
        }
    }

    #[cfg(feature = "https")]
    pub(crate) fn merge_with(&self, other: &Uri) -> Uri<'a> {
        let scheme = match (self.scheme, other.scheme) {
            (None, Some(s)) => Some(s),
            (Some(s), _) => Some(s),
            _ => None,
        };

        let host = match (self.host, other.host) {
            (None, Some(s)) => Some(s),
            (Some(s), _) => Some(s),
            _ => None,
        };

        let port = match (self.port, other.port) {
            (None, Some(s)) => Some(s.to_string()),
            (Some(s), _) => Some(s.to_string()),
            _ => None,
        };

        let path = match (self.path, other.path) {
            (Some(s), None) => Some(s),
            (_, Some(s)) => Some(s),
            _ => None,
        };

        let query = match (self.query, other.query) {
            (Some(s), None) => Some(s),
            (_, Some(s)) => Some(s),
            _ => None,
        };

        let uri = format!(
            "{}{}{}{}{}",
            scheme.unwrap_or_default(),
            host.unwrap_or_default(),
            port.as_ref().map(|p| format!(":{}", p)).unwrap_or_default(),
            path.unwrap_or_default(),
            query
                .as_ref()
                .map(|q| format!("?{}", q))
                .unwrap_or_default()
        );
        Uri::from(uri)
    }

    pub(crate) fn same_host_as(&self, other: &Uri) -> bool {
        other.kind() == UriKind::AbsolutePath || self.host == other.host && self.port == other.port
    }

    pub(crate) fn host_and_port(&self) -> Option<String> {
        match (self.host, self.port) {
            (Some(h), Some(p)) => format!("{h}:{p}").into(),
            (_, _) => None,
        }
    }

    pub(crate) fn update_references(&'a mut self) {
        fn find_scheme(value: &str) -> Option<&str> {
            match value.find("://") {
                None => None,
                Some(i) => Some(&value[..i + 3]),
            }
        }

        fn find_host(value: &str) -> Option<&str> {
            match value.starts_with('/') {
                true => None,
                false => {
                    let start = match value.find("://") {
                        None => 0,
                        Some(x) => x + 3,
                    };

                    let end = match value[start..].find(':') {
                        None => match value[start..].find('/') {
                            None => value.len(),
                            Some(s) => s + start,
                        },
                        Some(s) => s + start,
                    };

                    Some(&value[start..end])
                }
            }
        }

        fn scheme_to_port(value: &str) -> Option<u16> {
            match find_scheme(value) {
                None => None,
                Some(s) => match s {
                    "http://" => Some(80),
                    "https://" => Some(443),
                    _ => None,
                },
            }
        }

        fn find_port(value: &str) -> Option<u16> {
            let start = match value.find("://") {
                None => 0,
                Some(x) => x + 3,
            };

            let end = match value[start..].find('/') {
                None => value.len(),
                Some(x) => x + start,
            };

            match value[start..end].find(':') {
                None => scheme_to_port(value),
                Some(p) => match value[p + start + 1..end].parse::<u16>() {
                    Ok(p) => Some(p),
                    Err(_) => None,
                },
            }
        }

        fn slice_path(value: &str) -> (Option<&str>, Option<&str>, Option<&str>) {
            let start = match value.starts_with('/') {
                true => 0,
                false => {
                    let scheme = match value.find("://") {
                        None => 0,
                        Some(x) => x + 3,
                    };

                    match value[scheme..].find("/") {
                        None => return (None, None, None),
                        Some(x) => x + scheme,
                    }
                }
            };

            let (end, query) = match value.find('?') {
                None => (value.len(), None),
                Some(x) => (x, Some(&value[x + 1..])),
            };

            (Some(&value[start..end]), query, Some(&value[start..]))
        }

        self.scheme = find_scheme(&self.uri);
        self.host = find_host(&self.uri);
        self.port = find_port(&self.uri);
        (self.path, self.query, self.path_and_query) = slice_path(&self.uri);
    }
}

pub(crate) trait AsyncReadWriteExt: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWriteExt for T {}

enum StreamType {
    Disconnected,
    Unencrypted(TcpStream),
    #[cfg(feature = "https")]
    TlsClient(client::TlsStream<TcpStream>),
    //#[cfg(feature = "https")]
    //TlsServer(server::TlsStream<TcpStream>),
}

pub(crate) struct FetchRequest<'a> {
    uri: Uri<'a>,
    stream: StreamType,
}

#[derive(Debug)]
pub(crate) enum FetchRequestError {
    InvalidScheme,
    InvalidUri,
    #[cfg(feature = "https")]
    InvalidDomainName(String),
    TcpConnectionError(String),
    #[cfg(feature = "https")]
    TlsConnectionError(String),
}

impl fmt::Display for FetchRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InvalidScheme => write!(f, "Uri had no scheme"),
            InvalidUri => write!(f, "Invalid Uri"),
            #[cfg(feature = "https")]
            InvalidDomainName(name) => write!(f, "Invalid domain name: {}", name),
            TcpConnectionError(msg) => write!(f, "TCP connection error: {}", msg),
            #[cfg(feature = "https")]
            TlsConnectionError(msg) => write!(f, "TLS connection error: {}", msg),
        }
    }
}

impl FetchRequest<'_> {
    pub(crate) fn from_uri(value: &Uri<'_>) -> Result<Self, FetchRequestError> {
        let stream = Disconnected;

        let uri = Uri::from(&value.uri);
        Ok(FetchRequest { uri, stream })
    }

    #[allow(dead_code)]
    pub(crate) fn from_string(value: &String) -> Result<Self, FetchRequestError> {
        let stream = Disconnected;

        let uri = Uri::from(value);
        Ok(FetchRequest { uri, stream })
    }

    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    pub(crate) async fn connect(
        &mut self,
        #[cfg(feature = "https")] certificates: &crate::cert::CertificateSetup,
    ) -> Result<(), FetchRequestError> {
        let value = &self.uri;

        let host = match value.host_and_port() {
            Some(s) => s,
            None => return Err(InvalidUri),
        };

        let scheme = match value.scheme {
            None => return Err(InvalidScheme),
            Some(s) => s,
        };

        match scheme {
            "http://" => {
                let stream = match TcpStream::connect(host).await {
                    Ok(o) => Unencrypted(o),
                    Err(e) => return Err(TcpConnectionError(e.to_string())),
                };

                self.stream = stream;
                Ok(())
            }
            #[cfg(feature = "https")]
            "https://" => {
                let dns = match value.host {
                    None => return Err(InvalidUri),
                    Some(o) => o.to_string(),
                };

                use tokio_rustls::rustls::pki_types::ServerName;
                let domain = match ServerName::try_from(dns) {
                    Ok(d) => d,
                    Err(e) => return Err(InvalidDomainName(e.to_string())),
                };

                let stream = match TcpStream::connect(host).await {
                    Ok(o) => o,
                    Err(e) => return Err(TcpConnectionError(e.to_string())),
                };

                let stream: StreamType =
                    match certificates.client_config.connect(domain, stream).await {
                        Ok(s) => TlsClient(s),
                        Err(e) => return Err(TlsConnectionError(e.to_string())),
                    };

                self.stream = stream;
                Ok(())
            }
            _ => Err(InvalidScheme),
        }
    }

    pub(crate) async fn redirect(
        &mut self,
        other: &Uri<'_>,
        #[cfg(feature = "https")] certificates: &crate::cert::CertificateSetup,
    ) -> Result<(), FetchRequestError> {
        let compare = &self.uri;

        match compare.same_host_as(other) {
            true => {
                if let Some(new_path) = other.path_and_query {
                    let new = format!(
                        "{}{}{}",
                        compare.scheme.unwrap_or_default(),
                        compare.host_and_port().unwrap(),
                        new_path
                    );
                    self.uri = Uri::from(new);
                    return Ok(());
                }
                Err(InvalidUri)
            }
            false => {
                self.uri = Uri::from(other);
                match self
                    .connect(
                        #[cfg(feature = "https")]
                        certificates,
                    )
                    .await
                {
                    Ok(o) => o,
                    Err(e) => return Err(e),
                }

                Ok(())
            }
        }
    }

    pub(crate) fn as_stream(&mut self) -> Option<Pin<Box<dyn AsyncReadWriteExt + '_>>> {
        match self.stream {
            Disconnected => None,
            Unencrypted(ref mut stream) => Some(Box::pin(stream)),
            #[cfg(feature = "https")]
            TlsClient(ref mut stream) => Some(Box::pin(stream)),
            //#[cfg(feature = "https")]
            //TlsServer(ref mut stream) => Some(Box::pin(stream)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_absolute_address() {
        let uri = Uri::new("http://example.com/path".to_string());
        assert_eq!(uri.kind(), UriKind::AbsoluteAddress);
        assert_eq!(uri.scheme, Some("http://"));
        assert_eq!(uri.host, Some("example.com"));
        assert_eq!(uri.port, Some(80));
        assert_eq!(uri.path, Some("/path"));
        assert_eq!(uri.query, None);
        assert_eq!(uri.path_and_query, uri.path);
    }

    #[test]
    fn test_uri_absolute_address_with_query() {
        let uri = Uri::new("http://example.com/path?query=something".to_string());
        assert_eq!(uri.kind(), UriKind::AbsoluteAddress);
        assert_eq!(uri.scheme, Some("http://"));
        assert_eq!(uri.host, Some("example.com"));
        assert_eq!(uri.port, Some(80));
        assert_eq!(uri.path, Some("/path"));
        assert_eq!(uri.query, Some("query=something"));
        assert_eq!(uri.path_and_query, Some("/path?query=something"));
    }

    #[test]
    fn test_uri_absolute_address_with_port() {
        let uri = Uri::new("https://example.com:8443/path?query=something".to_string());
        assert_eq!(uri.kind(), UriKind::AbsoluteAddress);
        assert_eq!(uri.scheme, Some("https://"));
        assert_eq!(uri.host, Some("example.com"));
        assert_eq!(uri.port, Some(8443));
        assert_eq!(uri.path, Some("/path"));
        assert_eq!(uri.query, Some("query=something"));
        assert_eq!(uri.path_and_query, Some("/path?query=something"));
    }

    #[test]
    fn test_uri_relative_address() {
        let uri = Uri::new("example.com/path?query=something".to_string());
        assert_eq!(uri.kind(), UriKind::RelativeAddress);
        assert_eq!(uri.scheme, None);
        assert_eq!(uri.host, Some("example.com"));
        assert_eq!(uri.port, None);
        assert_eq!(uri.path, Some("/path"));
        assert_eq!(uri.query, Some("query=something"));
        assert_eq!(uri.path_and_query, Some("/path?query=something"));
    }

    #[test]
    fn test_uri_absolute_path() {
        let uri = Uri::new("/path/to/resource".to_string());
        assert_eq!(uri.kind(), UriKind::AbsolutePath);
        assert_eq!(uri.scheme, None);
        assert_eq!(uri.host, None);
        assert_eq!(uri.port, None);
        assert_eq!(uri.path, Some("/path/to/resource"));
        assert_eq!(uri.query, None);
        assert_eq!(uri.path_and_query, Some("/path/to/resource"));
    }

    #[test]
    fn test_uri_absolute_path_with_query() {
        let uri = Uri::new("/path/to/resource?query=something".to_string());
        assert_eq!(uri.kind(), UriKind::AbsolutePath);
        assert_eq!(uri.scheme, None);
        assert_eq!(uri.host, None);
        assert_eq!(uri.port, None);
        assert_eq!(uri.path, Some("/path/to/resource"));
        assert_eq!(uri.query, Some("query=something"));
        assert_eq!(
            uri.path_and_query,
            Some("/path/to/resource?query=something")
        );
    }

    #[test]
    fn test_uri_invalid() {
        let uri = Uri::new("not_a_valid_uri".to_string());
        assert_eq!(uri.kind(), UriKind::Invalid);
        assert_eq!(uri.scheme, None);
        assert_eq!(uri.host, None);
        assert_eq!(uri.port, None);
        assert_eq!(uri.path, None);
        assert_eq!(uri.query, None);
        assert_eq!(uri.path_and_query, None);
    }
}
