use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{self, Duration, Instant};

const END_OF_HTTP_HEADER: &[u8] = "\r\n\r\n".as_bytes();

pub enum HttpRequestMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH,
    CUSTOM(String),
}

impl From<&str> for HttpRequestMethod {
    fn from(input: &str) -> HttpRequestMethod {
        match input.to_uppercase().as_str() {
            "GET" => HttpRequestMethod::GET,
            "POST" => HttpRequestMethod::POST,
            "PUT" => HttpRequestMethod::PUT,
            "DELETE" => HttpRequestMethod::DELETE,
            "HEAD" => HttpRequestMethod::HEAD,
            "OPTIONS" => HttpRequestMethod::OPTIONS,
            "TRACE" => HttpRequestMethod::TRACE,
            "CONNECT" => HttpRequestMethod::CONNECT,
            "PATCH" => HttpRequestMethod::PATCH,
            _ => HttpRequestMethod::CUSTOM(input.to_uppercase()),
        }
    }
}

impl std::fmt::Display for HttpRequestMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpRequestMethod::GET => write!(f, "GET"),
            HttpRequestMethod::POST => write!(f, "POST"),
            HttpRequestMethod::PUT => write!(f, "PUT"),
            HttpRequestMethod::DELETE => write!(f, "DELETE"),
            HttpRequestMethod::HEAD => write!(f, "HEAD"),
            HttpRequestMethod::OPTIONS => write!(f, "OPTIONS"),
            HttpRequestMethod::TRACE => write!(f, "TRACE"),
            HttpRequestMethod::CONNECT => write!(f, "CONNECT"),
            HttpRequestMethod::PATCH => write!(f, "PATCH"),
            HttpRequestMethod::CUSTOM(s) => write!(f, "{}", s),
        }
    }
}

#[allow(dead_code)]
pub struct HttpRequestHeader {
    pub method: HttpRequestMethod,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

fn get_mandatory_http_request_header_line(line: &str) -> Option<(HttpRequestMethod, &str, &str)> {
    let elements: Vec<&str> = line.split_whitespace().collect();
    if elements.len() < 3 {
        return None;
    }

    let method = HttpRequestMethod::from(elements[0]);
    let path = elements[1];
    if !path.starts_with('/') {
        return None;
    }

    let version = elements[2];
    if !version.to_uppercase().contains("HTTP") {
        return None;
    }

    Some((method, path, version))
}

impl HttpRequestHeader {
    #[allow(dead_code)]
    pub async fn from_tcp_buffer_async(mut value: BufReader<&mut TcpStream>) -> Option<Self> {
        let mut buffer = Vec::new();
        let mut buffer_size: usize = 0;
        let begin = Instant::now();

        while !buffer.ends_with(END_OF_HTTP_HEADER) {
            match time::timeout(
                Duration::from_secs(10),
                value.read_until(
                    END_OF_HTTP_HEADER[END_OF_HTTP_HEADER.len() - 1],
                    &mut buffer,
                ),
            )
            .await
            {
                Ok(Ok(i)) => {
                    buffer_size += i;
                    if buffer_size >= 8192 {
                        return None;
                    }
                }
                Ok(Err(_)) | Err(_) => return None,
            }

            if begin.elapsed() >= Duration::from_secs(60) {
                return None;
            }
        }

        let header = String::from_utf8_lossy(&buffer);
        let lines: Vec<String> = header.split("\r\n").map(|s| s.to_string()).collect();
        let mandatory_line = match lines.get(0) {
            None => return None,
            Some(s) => s,
        };
        let (method, path, version) = match get_mandatory_http_request_header_line(mandatory_line) {
            None => return None,
            Some((a, b, c)) => (a, b, c),
        };
        let mut headers = HashMap::<String, String>::new();

        for line in lines.iter().skip(1) {
            let mut header = line.splitn(2, '\'');
            let property = match header.next() {
                Some(p) => p.to_string(),
                None => continue,
            };
            let value = header.next().unwrap_or_default().to_string();
            headers.insert(property, value);
        }

        let path = path.to_string();
        let version = version.to_string();

        Some(HttpRequestHeader {
            method,
            path,
            version,
            headers,
        })
    }

    #[allow(dead_code)]
    pub fn from_tcp_buffer(value: BufReader<&mut TcpStream>) -> Option<HttpRequestHeader> {
        match tokio::runtime::Handle::current()
            .block_on(HttpRequestHeader::from_tcp_buffer_async(value))
        {
            Some(header) => Some(header),
            None => None,
        }
    }
}
