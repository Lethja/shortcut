#[allow(dead_code)]
pub(crate) struct Uri {
    pub(crate) uri: String,
    /* TODO: Store each slice and make String the owner */
    pub(crate) scheme: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) path: Option<String>,
    pub(crate) query: Option<String>,
}

pub(crate) enum UriKind {
    AbsoluteAddress,
    AbsolutePath,
    RelativeAddress,
    RelativePath,
    Invalid,
}

impl From<String> for Uri {
    fn from(uri: String) -> Self {
        fn find_scheme(value: &str) -> Option<String> {
            match value.find("://") {
                None => None,
                Some(i) => Some((&value[..i + 2]).to_string()),
            }
        }

        fn find_host(value: &str) -> Option<String> {
            match value.starts_with('/') {
                true => None,
                false => {
                    let start = value.find("://").unwrap_or(0);
                    let end = match value[start..].find(':') {
                        None => match value[start..].find('/') {
                            None => value.len(),
                            Some(s) => s,
                        },
                        Some(s) => s,
                    };

                    Some((&value[start..end]).to_string())
                }
            }
        }

        fn scheme_to_port(value: &str) -> Option<u16> {
            match find_scheme(value) {
                None => None,
                Some(s) => match s.as_str() {
                    "http" => Some(80),
                    "https" => Some(443),
                    _ => None,
                },
            }
        }

        fn find_port(value: &str) -> Option<u16> {
            let start = value.find("://").unwrap_or(0);
            let end = value[start + 2..].find('/').unwrap_or(value.len());

            match value[start + 2..end].find(':') {
                None => scheme_to_port(value),
                Some(p) => match value[p..].parse::<u16>() {
                    Ok(p) => Some(p),
                    Err(_) => None,
                },
            }
        }

        fn find_path(value: &str) -> Option<String> {
            let start = match value.starts_with('/') {
                true => 0,
                false => {
                    let scheme = match value.find("://") {
                        None => 0,
                        Some(x) => x + 3,
                    };

                    let host = match value[scheme..].find("/") {
                        None => return None,
                        Some(x) => x + 1,
                    };

                    host
                }
            };

            let end = value.find('?').unwrap_or(value.len());
            Some((&value[start..end]).to_string())
        }

        fn find_query(value: &str) -> Option<String> {
            let scheme = match value.find("://") {
                None => 0,
                Some(x) => x + 3,
            };

            let host = match value[scheme..].find("/") {
                None => return None,
                Some(x) => x + 1,
            };

            let path = match value[host..].find("?") {
                None => return None,
                Some(x) => x + 1,
            };

            let query = match value[path..].find("?") {
                None => return None,
                Some(x) => x + 1,
            };

            Some((&value[query..]).to_string())
        }

        let scheme = find_scheme(&uri);
        let host = find_host(&uri);
        let port = find_port(&uri);
        let path = find_path(&uri);
        let query = find_query(&uri);

        Uri {
            uri,
            scheme,
            host,
            port,
            path,
            query,
        }
    }
}

impl Uri {
    pub(crate) fn kind(&self) -> UriKind {
        if (self.scheme.is_some() || self.port.is_some())
            && self.host.is_some()
            && self.path.is_some()
        {
            return UriKind::AbsoluteAddress;
        }

        if self.host.is_some() && self.path.is_some() {
            return UriKind::RelativeAddress;
        }

        if let Some(path) = &self.path {
            if path.starts_with('/') {
                return UriKind::AbsolutePath;
            } else {
                return UriKind::RelativePath;
            }
        }

        UriKind::Invalid
    }
}
