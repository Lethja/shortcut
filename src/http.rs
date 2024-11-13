use crate::conn::{Uri, UriKind};
use crate::http::ConnectionReturn::{Close, Keep};
use std::{
    collections::HashMap,
    fmt::Formatter,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::{
    fs::{remove_file, File},
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    join,
    time::{self, timeout, Duration, Instant},
};

const END_OF_HTTP_HEADER: &str = "\r\n\r\n";

const END_OF_HTTP_HEADER_LINE: &str = "\r\n";

pub const X_PROXY_CACHE_PATH: &str = "X_PROXY_CACHE_PATH";

/* 16 kibi-bytes will occupy half of l1d on a typical x86_64 core */
pub const BUFFER_SIZE: usize = 16384;
const WAIT_TIMEOUT_SECONDS: u64 = 10;

pub(crate) enum ConnectionReturn {
    Close,
    Keep,
    #[cfg(feature = "https")]
    Redirect(String),
    #[cfg(feature = "https")]
    Upgrade(String),
}

pub(crate) enum HttpRequestMethod {
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

impl PartialEq for HttpRequestMethod {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HttpRequestMethod::Get, HttpRequestMethod::Get) => true,
            (HttpRequestMethod::Post, HttpRequestMethod::Post) => true,
            (HttpRequestMethod::Put, HttpRequestMethod::Put) => true,
            (HttpRequestMethod::Delete, HttpRequestMethod::Delete) => true,
            (HttpRequestMethod::Head, HttpRequestMethod::Head) => true,
            (HttpRequestMethod::Options, HttpRequestMethod::Options) => true,
            (HttpRequestMethod::Trace, HttpRequestMethod::Trace) => true,
            (HttpRequestMethod::Connect, HttpRequestMethod::Connect) => true,
            (HttpRequestMethod::Patch, HttpRequestMethod::Patch) => true,
            (HttpRequestMethod::Custom(x), HttpRequestMethod::Custom(y)) => x == y,
            _ => false,
        }
    }
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

pub struct HttpVersion(u16);

impl HttpVersion {
    pub const HTTP_V09: Self = HttpVersion(9);
    pub const HTTP_V10: Self = HttpVersion(10);
    pub const HTTP_V11: Self = HttpVersion(11);

    pub(crate) fn as_str(&self) -> &str {
        match self.0 {
            10 => "HTTP/1.0",
            11 => "HTTP/1.1",
            _ => "",
        }
    }

    pub(crate) fn from(str: &str) -> Self {
        match str {
            "HTTP/1.0" => Self::HTTP_V10,
            "HTTP/1.1" => Self::HTTP_V11,
            _ => Self::HTTP_V09,
        }
    }
}

pub(crate) fn keep_alive_if(header: &HttpRequestHeader) -> ConnectionReturn {
    match header.version {
        HttpVersion(11) => match header.headers.get("Connection") {
            None => Keep,
            Some(v) => {
                if v == "Close" {
                    Close
                } else {
                    Keep
                }
            }
        },
        HttpVersion(10) => match header.headers.get("Connection") {
            None => Close,
            Some(v) => {
                if v == "Close" {
                    Close
                } else {
                    Keep
                }
            }
        },
        _ => Close,
    }
}

pub struct HttpRequestHeader<'a> {
    pub method: HttpRequestMethod,
    pub request: Uri<'a>,
    pub version: HttpVersion,
    pub headers: HashMap<String, String>,
}

fn get_mandatory_http_request_header_line(
    line: &str,
) -> Option<(HttpRequestMethod, String, HttpVersion)> {
    let elements: Vec<&str> = line.split_whitespace().collect();
    if elements.len() < 3 {
        return None;
    }

    let method = HttpRequestMethod::from(elements[0]);
    let path = elements[1].to_string();
    if method == HttpRequestMethod::Get && !path.starts_with('/') && !path.contains("://") {
        return None;
    }

    let version = elements[2];
    let version = match version.to_uppercase().as_str() {
        "HTTP/1.0" => HttpVersion::HTTP_V10,
        "HTTP/1.1" => HttpVersion::HTTP_V11,
        _ => HttpVersion::HTTP_V09,
    };

    Some((method, path, version))
}

fn get_mandatory_http_response_header_line(
    line: &str,
) -> Option<(HttpResponseStatus, HttpVersion)> {
    let elements: Vec<&str> = line.splitn(3, ' ').collect();
    if elements.len() < 2 {
        return None;
    }

    let status = match elements[1].parse::<u16>() {
        Ok(u) => HttpResponseStatus(u),
        Err(_) => return None,
    };
    let version = HttpVersion::from(elements[0]);

    Some((status, version))
}

fn assemble_mandatory_http_request_header_line(method: &str, path: &str, version: &str) -> String {
    format!("{method} {path} {version}")
}

pub(crate) async fn get_cache_name(url: &HttpRequestHeader<'_>) -> Option<PathBuf> {
    let store_path = match std::env::var(X_PROXY_CACHE_PATH) {
        Ok(s) => s,
        Err(e) => {
            return {
                eprintln!("{e}");
                None
            }
        }
    };

    let host = match url.request.host {
        None => "Unknown".to_string(),
        Some(s) => s.to_string(),
    };

    let file = match url.request.path {
        None => return None,
        Some(s) => {
            let p = PathBuf::from(s);
            match p.file_name().map(|s| s.to_string_lossy().to_string()) {
                None => return None,
                Some(p) => p,
            }
        }
    };

    let path = Path::new(&store_path).join(host).join(file);

    Some(path)
}

impl HttpRequestHeader<'_> {
    pub(crate) async fn from_tcp_buffer_async<T>(value: &mut BufReader<T>) -> Option<Self>
    where
        T: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut buffer = Vec::new();
        let mut buffer_size: usize = 0;
        let begin = Instant::now();
        let filter = END_OF_HTTP_HEADER.as_bytes();

        while !buffer.ends_with(filter) {
            match time::timeout(
                Duration::from_secs(10),
                value.read_until(filter[filter.len() - 1], &mut buffer),
            )
            .await
            {
                Ok(Ok(i)) => {
                    buffer_size += i;
                    if buffer_size >= BUFFER_SIZE {
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
        let lines: Vec<String> = header
            .split(END_OF_HTTP_HEADER_LINE)
            .map(|s| s.to_string())
            .collect();
        let mandatory_line = match lines.first() {
            None => return None,
            Some(s) => s,
        };
        let (method, request, version) =
            match get_mandatory_http_request_header_line(mandatory_line) {
                None => return None,
                Some((a, b, c)) => (a, b, c),
            };
        let headers = get_http_headers(&lines);
        consume_http_header(value);

        let request = Uri::from(request);

        match request.kind() {
            UriKind::Invalid | UriKind::RelativeAddress => None,
            _ => Some(HttpRequestHeader {
                method,
                request,
                version,
                headers,
            }),
        }
    }

    pub(crate) fn generate(&self) -> Option<String> {
        let path = match self.request.path {
            None => return None,
            Some(p) => p,
        };

        let mut str = assemble_mandatory_http_request_header_line(
            self.method.to_string().as_str(),
            path,
            self.version.as_str(),
        );
        for (key, value) in &self.headers {
            if !key.trim().is_empty() && !value.trim().is_empty() {
                str.push_str(&format!("{END_OF_HTTP_HEADER_LINE}{key}: {value}"))
            }
        }
        str.push_str(END_OF_HTTP_HEADER);
        Some(str)
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

    pub(crate) fn to_description(&self) -> &'static str {
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

    pub(crate) fn to_code(&self) -> u16 {
        self.0
    }

    fn to_header(&self) -> String {
        let code = self.0;
        let str = self.to_description().to_uppercase();
        let date = httpdate::fmt_http_date(SystemTime::now());
        format!("HTTP/1.1 {code} {str}{END_OF_HTTP_HEADER_LINE}Date: {date}")
    }

    pub(crate) fn to_empty_response(&self) -> String {
        let code = self.0;
        let str = self.to_description().to_uppercase();
        let date = httpdate::fmt_http_date(SystemTime::now());
        format!("HTTP/1.1 {code} {str}{END_OF_HTTP_HEADER_LINE}Date: {date}{END_OF_HTTP_HEADER}")
    }

    pub(crate) fn to_response(&self) -> String {
        let code = self.0;
        let msg = self.to_description();
        let len = msg.len();
        let state = msg.to_uppercase();
        let date = httpdate::fmt_http_date(SystemTime::now());

        format!("HTTP/1.1 {code} {state}{END_OF_HTTP_HEADER_LINE}Date: {date}{END_OF_HTTP_HEADER_LINE}Content-length: {len}{END_OF_HTTP_HEADER}{msg}")
    }
}

pub struct HttpResponseHeader {
    pub status: HttpResponseStatus,
    pub headers: HashMap<String, String>,
    #[allow(dead_code)]
    pub version: HttpVersion,
}

fn get_http_headers(lines: &[String]) -> HashMap<String, String> {
    let mut headers = HashMap::<String, String>::new();

    for line in lines.iter().skip(1) {
        let mut header = line.splitn(2, ':');
        let property = match header.next() {
            Some(p) => p.trim().to_string(),
            None => continue,
        };
        let value = header.next().unwrap_or_default().trim().to_string();
        headers.insert(property, value);
    }
    headers
}

fn consume_http_header<T>(value: &mut BufReader<T>)
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    if let Some(pos) = value
        .buffer()
        .windows(END_OF_HTTP_HEADER.len())
        .position(|window| window == END_OF_HTTP_HEADER.as_bytes())
    {
        value.consume(pos + END_OF_HTTP_HEADER.len());
    }
}

impl HttpResponseHeader {
    pub(crate) async fn from_tcp_buffer_async<T>(value: &mut BufReader<T>) -> Option<Self>
    where
        T: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut buffer = Vec::new();
        let mut buffer_size: usize = 0;
        let begin = Instant::now();
        let filter = END_OF_HTTP_HEADER.as_bytes();

        while !buffer.ends_with(filter) {
            match time::timeout(
                Duration::from_secs(5),
                value.read_until(filter[filter.len() - 1], &mut buffer),
            )
            .await
            {
                Ok(Ok(i)) => {
                    buffer_size += i;
                    if buffer_size >= BUFFER_SIZE {
                        return None;
                    }
                }
                Ok(Err(_)) | Err(_) => return None,
            }

            if begin.elapsed() >= Duration::from_secs(10) {
                return None;
            }
        }

        let headers = String::from_utf8_lossy(&buffer);
        let lines: Vec<String> = headers
            .split(END_OF_HTTP_HEADER_LINE)
            .map(|s| s.to_string())
            .collect();
        let mandatory_line = match lines.first() {
            None => return None,
            Some(s) => s,
        };
        let (status, version) = match get_mandatory_http_response_header_line(mandatory_line) {
            None => return None,
            Some((a, b)) => (a, b),
        };

        let headers = get_http_headers(&lines);
        consume_http_header(value);

        Some(HttpResponseHeader {
            status,
            headers,
            version,
        })
    }

    pub(crate) fn generate(&mut self) -> String {
        if !self.headers.contains_key("Date") {
            self.headers.insert(
                String::from("Date"),
                httpdate::fmt_http_date(SystemTime::now()),
            );
        }

        let mut str = self.status.to_header();
        for (key, value) in &self.headers {
            if !key.trim().is_empty() && !value.trim().is_empty() {
                str.push_str(&format!("{END_OF_HTTP_HEADER_LINE}{key}: {value}"));
            }
        }
        str.push_str(END_OF_HTTP_HEADER);
        str
    }
}

pub(crate) async fn fetch_and_serve_known_length<T, R>(
    cache_file_path: &PathBuf,
    stream: &mut T,
    mut content_length: u64,
    mut fetch_buf_reader: R,
    file: &mut File,
) -> (bool, bool)
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
    R: AsyncBufRead + Unpin,
{
    let mut buffer = vec![0; BUFFER_SIZE];

    let mut write_file = true;
    let mut write_stream = true;

    loop {
        if content_length == 0 {
            break;
        }

        let fetch = match timeout(
            Duration::from_secs(WAIT_TIMEOUT_SECONDS),
            fetch_buf_reader.read(&mut buffer),
        )
        .await
        {
            Ok(f) => f,
            Err(_) => return (false, false),
        };

        match fetch {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                content_length -= n as u64;
                let data = &buffer[..n];

                match (write_file, write_stream) {
                    (true, true) => {
                        let file_write_future = file.write_all(data);
                        let client_write_future = stream.write_all(data);

                        match join!(file_write_future, client_write_future) {
                            (Err(_), _) => {
                                write_file = false;
                                if cache_file_path.exists() {
                                    /* The file is in an unknown state and should be removed */
                                    let _ = remove_file(&cache_file_path).await;
                                }
                            }
                            (_, Err(_)) => write_stream = false,
                            _ => {}
                        }
                    }
                    (true, false) => match file.write_all(data).await {
                        Ok(_) => {}
                        Err(_) => {
                            if cache_file_path.exists() {
                                /* The file is in an unknown state and should be removed */
                                let _ = remove_file(&cache_file_path).await;
                            }
                            return (false, false);
                        }
                    },
                    (false, true) => match stream.write_all(data).await {
                        Ok(_) => {}
                        Err(_) => return (false, false),
                    },
                    (false, false) => return (false, false),
                }
            }
            Err(_) => return (false, false),
        }
    }

    (write_file, write_stream)
}

pub(crate) async fn fetch_and_serve_chunk<T, R>(
    cache_file_path: &PathBuf,
    stream: &mut T,
    fetch_buf_reader: &mut BufReader<R>,
    file: &mut File,
) -> (bool, bool)
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
    R: AsyncReadExt + AsyncWriteExt + Unpin,
{
    async fn parse_http_chunk(buffer: &mut [u8]) -> Option<u64> {
        let size = match String::from_utf8(buffer.to_vec()) {
            Ok(s) => match u64::from_str_radix(s.trim(), 16) {
                Ok(value) => value,
                Err(_) => return None,
            },
            Err(_) => return None,
        };

        Some(size)
    }
    async fn get_http_chunk<T>(reader: &mut T, is_start: bool) -> Option<Vec<u8>>
    where
        T: AsyncBufRead + Unpin,
    {
        let format = END_OF_HTTP_HEADER_LINE.as_bytes();
        let mut buffer: Vec<u8> = vec![0; BUFFER_SIZE];

        let mut i: usize = 2;

        let read = match timeout(
            Duration::from_secs(WAIT_TIMEOUT_SECONDS),
            reader.read(&mut buffer[..i]),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => return None,
        };

        match read {
            Ok(d) => {
                if !is_start && (d != 2 || buffer[0] != format[0] || buffer[1] != format[1]) {
                    return None;
                }

                let mut byte = [0u8; 1];
                while let Ok(d) = reader.read(&mut byte).await {
                    if d == 0 {
                        break;
                    }
                    buffer[i] = byte[0];
                    if buffer.len() > 2 && buffer[i - 1] == format[0] && buffer[i] == format[1] {
                        break;
                    }

                    if i >= BUFFER_SIZE {
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            Err(_) => return None,
        }
        Some(buffer[..i + 1].to_vec())
    }

    let filter_line = END_OF_HTTP_HEADER_LINE.as_bytes();
    let mut buffer = vec![0; BUFFER_SIZE];

    let mut write_file = true;
    let mut write_stream = true;

    let mut content_length = match get_http_chunk(fetch_buf_reader, true).await {
        Some(mut s) => {
            match stream.write_all(&s).await {
                Ok(_) => {}
                Err(_) => write_stream = false,
            }

            match parse_http_chunk(s.as_mut_slice()).await {
                Some(length) => {
                    if length == 0 {
                        let _ = stream.write_all(filter_line).await;
                        return (true, true);
                    }

                    length
                }
                None => return (false, false),
            }
        }
        None => return (false, false),
    };

    loop {
        if content_length == 0 {
            match get_http_chunk(fetch_buf_reader, false).await {
                Some(mut s) => {
                    if write_stream {
                        match stream.write_all(s.as_slice()).await {
                            Ok(_) => {}
                            Err(_) => write_stream = false,
                        }
                    }

                    content_length = match parse_http_chunk(s.as_mut_slice()).await {
                        None => return (false, false),
                        Some(length) => {
                            if length == 0 {
                                let _ = stream.write_all(filter_line).await;
                                return (true, true);
                            }

                            length
                        }
                    };
                }
                None => return (false, false),
            }

            continue;
        }

        let min = std::cmp::min(content_length as usize, BUFFER_SIZE);

        match fetch_buf_reader.read_exact(&mut buffer[..min]).await {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                content_length -= n as u64;
                let data = &buffer[..n];

                match (write_file, write_stream) {
                    (true, true) => {
                        let file_write_future = file.write_all(data);
                        let client_write_future = stream.write_all(data);

                        match join!(file_write_future, client_write_future) {
                            (Err(_), _) => {
                                write_file = false;
                                if cache_file_path.exists() {
                                    /* The file is in an unknown state and should be removed */
                                    let _ = remove_file(&cache_file_path).await;
                                }
                            }
                            (_, Err(_)) => write_stream = false,
                            _ => {}
                        }
                    }
                    (true, false) => match file.write_all(data).await {
                        Ok(_) => {}
                        Err(_) => {
                            if cache_file_path.exists() {
                                /* The file is in an unknown state and should be removed */
                                let _ = remove_file(&cache_file_path).await;
                            }
                            return (false, false);
                        }
                    },
                    (false, true) => match stream.write_all(data).await {
                        Ok(_) => {}
                        Err(_) => return (false, false),
                    },
                    (false, false) => return (false, false),
                }
            }
            Err(_) => return (false, false),
        }
    }

    (false, false)
}
