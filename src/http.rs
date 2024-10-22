use std::{collections::HashMap, fmt::Formatter, time::SystemTime};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
    time::{self, Duration, Instant},
};

const END_OF_HTTP_HEADER: &[u8] = "\r\n\r\n".as_bytes();

pub enum HttpRequestMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Patch,
    Custom(String),
}

impl From<&str> for HttpRequestMethod {
    fn from(input: &str) -> HttpRequestMethod {
        match input.to_uppercase().as_str() {
            "GET" => HttpRequestMethod::Get,
            "POST" => HttpRequestMethod::Post,
            "PUT" => HttpRequestMethod::Put,
            "DELETE" => HttpRequestMethod::Delete,
            "HEAD" => HttpRequestMethod::Head,
            "OPTIONS" => HttpRequestMethod::Options,
            "TRACE" => HttpRequestMethod::Trace,
            "CONNECT" => HttpRequestMethod::Connect,
            "PATCH" => HttpRequestMethod::Patch,
            _ => HttpRequestMethod::Custom(input.to_uppercase()),
        }
    }
}

impl std::fmt::Display for HttpRequestMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpRequestMethod::Get => write!(f, "GET"),
            HttpRequestMethod::Post => write!(f, "POST"),
            HttpRequestMethod::Put => write!(f, "PUT"),
            HttpRequestMethod::Delete => write!(f, "DELETE"),
            HttpRequestMethod::Head => write!(f, "HEAD"),
            HttpRequestMethod::Options => write!(f, "OPTIONS"),
            HttpRequestMethod::Trace => write!(f, "TRACE"),
            HttpRequestMethod::Connect => write!(f, "CONNECT"),
            HttpRequestMethod::Patch => write!(f, "PATCH"),
            HttpRequestMethod::Custom(s) => write!(f, "{}", s),
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
    if !path.starts_with('/') && !path.contains("://") {
        return None;
    }

    let version = elements[2];
    if !version.to_uppercase().contains("HTTP") {
        return None;
    }

    Some((method, path, version))
}

fn assemble_mandatory_http_request_header_line(method: &str, path: &str, version: &str) -> String {
    format!("{method} {path} {version}")
}

#[allow(dead_code)]
impl HttpRequestHeader {
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
        let mandatory_line = match lines.first() {
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

    pub fn from_tcp_buffer(value: BufReader<&mut TcpStream>) -> Option<HttpRequestHeader> {
        tokio::runtime::Handle::current().block_on(HttpRequestHeader::from_tcp_buffer_async(value))
    }

    pub fn is_absolute_path(&self) -> bool {
        match self.path.splitn(2, "://").next() {
            None => {false}
            Some(i) => {i.starts_with("http")}
        }
    }

    pub fn is_relative_path(&self) -> bool {
        self.path.starts_with('/')
    }

    pub fn get_path_without_query(&self) -> String {
        match self.path.splitn(2, '?').next() {
            None => {self.path.to_string()}
            Some(i) => {i.to_string()}
        }
    }

    pub fn get_query(&self) -> Option<String> {
        match self.path.find('?') {
            None => None,
            Some(i) => {
                let query = &self.path[i..];
                Some(query.to_string())
            }
        }
    }

    pub fn generate(&self) -> String {
        let mut str = assemble_mandatory_http_request_header_line(
            self.method.to_string().as_str(),
            self.path.as_str(),
            self.version.as_str(),
        );
        for (key, value) in &self.headers {
            str.push_str(&format!("\r\n{key}: {value}"))
        }
        str.push_str("\r\n\r\n");
        str
    }
}

pub struct HttpResponseStatus(u16);

#[allow(dead_code)]
impl HttpResponseStatus {
    pub const CONTINUE: Self = HttpResponseStatus(100);
    pub const SWITCHING_PROTOCOLS: Self = HttpResponseStatus(101);
    pub const PROCESSING: Self = HttpResponseStatus(102);
    pub const EARLY_HINTS: Self = HttpResponseStatus(103);
    pub const OK: Self = HttpResponseStatus(200);
    pub const CREATED: Self = HttpResponseStatus(201);
    pub const ACCEPTED: Self = HttpResponseStatus(202);
    pub const NON_AUTHORITATIVE_INFORMATION: Self = HttpResponseStatus(203);
    pub const NO_CONTENT: Self = HttpResponseStatus(204);
    pub const RESET_CONTENT: Self = HttpResponseStatus(205);
    pub const PARTIAL_CONTENT: Self = HttpResponseStatus(206);
    pub const MULTI_STATUS: Self = HttpResponseStatus(207);
    pub const ALREADY_REPORTED: Self = HttpResponseStatus(208);
    pub const IM_USED: Self = HttpResponseStatus(226);
    pub const MULTIPLE_CHOICES: Self = HttpResponseStatus(300);
    pub const MOVED_PERMANENTLY: Self = HttpResponseStatus(301);
    pub const FOUND: Self = HttpResponseStatus(302);
    pub const SEE_OTHER: Self = HttpResponseStatus(303);
    pub const NOT_MODIFIED: Self = HttpResponseStatus(304);
    pub const USE_PROXY: Self = HttpResponseStatus(305);
    pub const UNUSED: Self = HttpResponseStatus(306);
    pub const TEMPORARY_REDIRECT: Self = HttpResponseStatus(307);
    pub const PERMANENT_REDIRECT: Self = HttpResponseStatus(308);
    pub const BAD_REQUEST: Self = HttpResponseStatus(400);
    pub const UNAUTHORIZED: Self = HttpResponseStatus(401);
    pub const PAYMENT_REQUIRED: Self = HttpResponseStatus(402);
    pub const FORBIDDEN: Self = HttpResponseStatus(403);
    pub const NOT_FOUND: Self = HttpResponseStatus(404);
    pub const METHOD_NOT_ALLOWED: Self = HttpResponseStatus(405);
    pub const NOT_ACCEPTABLE: Self = HttpResponseStatus(406);
    pub const PROXY_AUTHENTICATION_REQUIRED: Self = HttpResponseStatus(407);
    pub const REQUEST_TIMEOUT: Self = HttpResponseStatus(408);
    pub const CONFLICT: Self = HttpResponseStatus(409);
    pub const GONE: Self = HttpResponseStatus(410);
    pub const LENGTH_REQUIRED: Self = HttpResponseStatus(411);
    pub const PRECONDITION_FAILED: Self = HttpResponseStatus(412);
    pub const CONTENT_TOO_LARGE: Self = HttpResponseStatus(413);
    pub const URI_TOO_LONG: Self = HttpResponseStatus(414);
    pub const UNSUPPORTED_MEDIA_TYPE: Self = HttpResponseStatus(415);
    pub const RANGE_NOT_SATISFIABLE: Self = HttpResponseStatus(416);
    pub const EXPECTATION_FAILED: Self = HttpResponseStatus(417);
    pub const IM_A_TEAPOT: Self = HttpResponseStatus(418);
    pub const MISDIRECTED_REQUEST: Self = HttpResponseStatus(421);
    pub const UNPROCESSABLE_CONTENT: Self = HttpResponseStatus(422);
    pub const LOCKED: Self = HttpResponseStatus(423);
    pub const FAILED_DEPENDENCY: Self = HttpResponseStatus(424);
    pub const TOO_EARLY: Self = HttpResponseStatus(425);
    pub const UPGRADE_REQUIRED: Self = HttpResponseStatus(426);
    pub const PRECONDITION_REQUIRED: Self = HttpResponseStatus(428);
    pub const TOO_MANY_REQUESTS: Self = HttpResponseStatus(429);
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: Self = HttpResponseStatus(431);
    pub const UNAVAILABLE_FOR_LEGAL_REASONS: Self = HttpResponseStatus(451);
    pub const INTERNAL_SERVER_ERROR: Self = HttpResponseStatus(500);
    pub const NOT_IMPLEMENTED: Self = HttpResponseStatus(501);
    pub const BAD_GATEWAY: Self = HttpResponseStatus(502);
    pub const SERVICE_UNAVAILABLE: Self = HttpResponseStatus(503);
    pub const GATEWAY_TIMEOUT: Self = HttpResponseStatus(504);
    pub const HTTP_VERSION_NOT_SUPPORTED: Self = HttpResponseStatus(505);
    pub const VARIANT_ALSO_NEGOTIATES: Self = HttpResponseStatus(506);
    pub const INSUFFICIENT_STORAGE: Self = HttpResponseStatus(507);
    pub const LOOP_DETECTED: Self = HttpResponseStatus(508);
    pub const NOT_EXTENDED: Self = HttpResponseStatus(510);
    pub const NETWORK_AUTHENTICATION_REQUIRED: Self = HttpResponseStatus(511);

    pub fn to_description(&self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",
            200 => "Ok",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            226 => "IM Used",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            306 => "Unused",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Content Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "I'm a teapot",
            421 => "Misdirected Request",
            422 => "Unprocessable Content",
            423 => "Locked",
            424 => "Failed Dependency",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            _ => "Unknown",
        }
    }

    pub fn to_code(&self) -> u16 {
        self.0
    }

    pub fn to_header(&self) -> String {
        let code = self.0;
        let str = self.to_description().to_uppercase();
        format!("{code} {str}")
    }

    pub fn to_response(&self) -> String {
        let code = self.0;
        let msg = self.to_description();
        let len = msg.len();
        let state = msg.to_uppercase();
        let date = httpdate::fmt_http_date(SystemTime::now());

        format!("HTTP/1.1 {code} {state}\r\nDate: {date}\r\nContent-length: {len}\r\n\r\n{msg}")
    }
}

pub struct HttpResponseHeader {
    pub status: HttpResponseStatus,
    pub headers: HashMap<String, String>,
}

#[allow(dead_code)]
impl HttpResponseHeader {
    pub fn new(status: HttpResponseStatus) -> Self {
        HttpResponseHeader {
            status,
            headers: Default::default(),
        }
    }

    pub fn generate(&mut self) -> String {
        if !self.headers.contains_key("Date") {
            self.headers.insert(
                String::from("Date"),
                httpdate::fmt_http_date(SystemTime::now()),
            );
        }

        let mut str = self.status.to_header();
        str.push_str("\r\n");
        for (key, value) in &self.headers {
            str.push_str(&format!("{}: {}\r\n", key, value));
        }
        str.push_str("\r\n");
        str
    }
}
