use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::{fs::File, io::Read};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone)]
struct ConfigFile {
    address: String,
    cache_max_age_seconds: u64,
    access_log: Option<PathBuf>,
    tls_certificate: Option<PathBuf>,
    tls_private_key: Option<PathBuf>,
    sites: Vec<SiteFile>,
    redirect_groups: Vec<RedirectGroup>,
    mime_types: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct SiteFile {
    host: String,
    document_root: PathBuf,
    index_file: String,
    not_found_page: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct Site {
    host: String,
    document_root: PathBuf,
    index_file: String,
    not_found_page: Option<PathBuf>,
    redirects: Vec<Redirect>,
}

#[derive(Debug, Clone)]
struct RedirectGroup {
    host: String,
    redirects: Vec<RedirectFile>,
}

#[derive(Debug, Clone)]
struct RedirectFile {
    path: String,
    target: String,
    status: u16,
}

#[derive(Debug, Clone)]
struct Redirect {
    path: String,
    target: String,
    status: u16,
}

#[derive(Debug, Clone)]
struct Config {
    address: String,
    cache_max_age_seconds: u64,
    access_log: Option<PathBuf>,
    tls: Option<TlsPaths>,
    sites: Vec<Site>,
    mime_types: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsPaths {
    certificate: PathBuf,
    private_key: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::var_os("NANO_SERVER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.ini"));
    let mut config_contents = fs::read_to_string(&config_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not read {}: {error}", config_path.display()),
        )
    })?;
    let mut config = load_config(&config_path, &config_contents)?;
    let bound_address = config.address.clone();
    let tls_config = load_tls_server_config(&config)?;

    let listener = TcpListener::bind(&config.address)?;
    let scheme = if tls_config.is_some() { "https" } else { "http" };
    println!(
        "Nano-Server serving {} site(s) at {scheme}://{}",
        config.sites.len(), config.address
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                match fs::read_to_string(&config_path) {
                    Ok(updated_contents) if updated_contents != config_contents => {
                        config_contents = updated_contents;
                        match load_config(&config_path, &config_contents) {
                            Ok(mut updated_config) => {
                                if updated_config.address != bound_address {
                                    eprintln!(
                                        "config reload: address changes require restarting the server; keeping {bound_address}"
                                    );
                                    updated_config.address = bound_address.clone();
                                }
                                if updated_config.tls != config.tls {
                                    eprintln!("config reload: TLS certificate changes require restarting the server; keeping current TLS settings");
                                    updated_config.tls = config.tls.clone();
                                }
                                config = updated_config;
                                println!("reloaded configuration from {}", config_path.display());
                            }
                            Err(error) => eprintln!(
                                "config reload failed; keeping last valid configuration: {error}"
                            ),
                        }
                    }
                    Ok(_) => {}
                    Err(error) => eprintln!(
                        "could not read updated config {}; keeping last valid configuration: {error}",
                        config_path.display()
                    ),
                }
                if let Err(error) = stream
                    .set_read_timeout(Some(REQUEST_TIMEOUT))
                    .and_then(|_| stream.set_write_timeout(Some(REQUEST_TIMEOUT)))
                {
                    eprintln!("could not set connection timeout: {error}");
                    continue;
                }
                let remote = stream
                    .peer_addr()
                    .map(|address| address.to_string())
                    .unwrap_or_else(|_| "unknown".to_owned());
                let config = config.clone();
                let tls_config = tls_config.clone();
                thread::spawn(move || {
                    let result = if let Some(tls_config) = tls_config {
                        match rustls::ServerConnection::new(tls_config) {
                            Ok(connection) => handle_connection(
                                rustls::StreamOwned::new(connection, stream),
                                remote,
                                &config,
                            ),
                            Err(error) => Err(io::Error::other(error)),
                        }
                    } else {
                        handle_connection(stream, remote, &config)
                    };
                    if let Err(error) = result {
                        eprintln!("connection error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept error: {error}"),
        }
    }

    Ok(())
}

fn load_tls_server_config(
    config: &Config,
) -> Result<Option<Arc<rustls::ServerConfig>>, Box<dyn std::error::Error>> {
    let Some(paths) = &config.tls else {
        return Ok(None);
    };
    let mut certificate_reader = BufReader::new(File::open(&paths.certificate)?);
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(format!("no certificates found in {}", paths.certificate.display()).into());
    }
    let mut key_reader = BufReader::new(File::open(&paths.private_key)?);
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| format!("no private key found in {}", paths.private_key.display()))?;
    let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)?;
    Ok(Some(Arc::new(server_config)))
}

fn load_config(config_path: &Path, contents: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let file = parse_config(contents)?;
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    let mut access_log = file.access_log;
    if let Some(path) = &mut access_log {
        if path.is_relative() {
            *path = parent.join(&*path);
        }
        if let Some(log_directory) = path.parent() {
            if !log_directory.as_os_str().is_empty() {
                fs::create_dir_all(log_directory)?;
            }
        }
    }
    let tls = match (file.tls_certificate, file.tls_private_key) {
        (Some(mut certificate), Some(mut private_key)) => {
            if certificate.is_relative() {
                certificate = parent.join(certificate);
            }
            if private_key.is_relative() {
                private_key = parent.join(private_key);
            }
            Some(TlsPaths {
                certificate,
                private_key,
            })
        }
        (None, None) => None,
        _ => return Err("tls_cert and tls_key must be configured together".into()),
    };
    let site_files = file.sites;

    let mut sites = Vec::with_capacity(site_files.len());
    for mut site_file in site_files {
        site_file.host = normalize_host(&site_file.host)
            .ok_or_else(|| format!("invalid site host: {}", site_file.host))?;
        if sites.iter().any(|site: &Site| site.host == site_file.host) {
            return Err(format!("duplicate site host: {}", site_file.host).into());
        }
        if site_file.document_root.is_relative() {
            site_file.document_root = parent.join(&site_file.document_root);
        }
        site_file.document_root = fs::canonicalize(&site_file.document_root)?;
        validate_index_file(&site_file.index_file)?;
        let mut redirects = Vec::new();
        let mut redirect_paths = std::collections::HashSet::new();
        for group in file
            .redirect_groups
            .iter()
            .filter(|group| normalize_host(&group.host).as_deref() == Some(site_file.host.as_str()))
        {
            for redirect in &group.redirects {
                validate_redirect(&redirect.path, &redirect.target)?;
                if !redirect_paths.insert(redirect.path.as_str()) {
                    return Err(format!(
                        "duplicate redirect for {} on {}",
                        redirect.path, site_file.host
                    )
                    .into());
                }
                redirects.push(Redirect {
                    path: redirect.path.clone(),
                    target: redirect.target.clone(),
                    status: redirect.status,
                });
            }
        }
        sites.push(Site {
            host: site_file.host,
            document_root: site_file.document_root,
            index_file: site_file.index_file,
            not_found_page: site_file.not_found_page,
            redirects,
        });
    }

    Ok(Config {
        address: file.address,
        cache_max_age_seconds: file.cache_max_age_seconds,
        access_log,
        tls,
        sites,
        mime_types: file.mime_types,
    })
}

fn parse_config(contents: &str) -> Result<ConfigFile, String> {
    #[derive(Clone, Copy)]
    enum Section {
        Server,
        Site(usize),
        Redirect(usize),
        Mime,
    }

    let mut config = ConfigFile {
        address: "127.0.0.1:8080".to_owned(),
        cache_max_age_seconds: 3600,
        access_log: None,
        tls_certificate: None,
        tls_private_key: None,
        sites: Vec::new(),
        redirect_groups: Vec::new(),
        mime_types: HashMap::new(),
    };
    let mut section = None;
    let mut server_seen = false;
    let mut mime_seen = false;
    let mut seen_keys = std::collections::HashSet::new();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim();
            if name == "server" {
                if server_seen {
                    return Err(format!("line {line_number}: duplicate [server] section"));
                }
                server_seen = true;
                section = Some(Section::Server);
            } else if let Some(host) = name.strip_prefix("site ") {
                let host = host.trim();
                if host.is_empty() {
                    return Err(format!("line {line_number}: site section needs a host"));
                }
                config.sites.push(SiteFile {
                    host: host.to_owned(),
                    document_root: PathBuf::new(),
                    index_file: "index.html".to_owned(),
                    not_found_page: None,
                });
                section = Some(Section::Site(config.sites.len() - 1));
            } else if let Some(host) = name.strip_prefix("redirect ") {
                let host = host.trim();
                if host.is_empty() {
                    return Err(format!("line {line_number}: redirect section needs a host"));
                }
                config.redirect_groups.push(RedirectGroup {
                    host: host.to_owned(),
                    redirects: Vec::new(),
                });
                section = Some(Section::Redirect(config.redirect_groups.len() - 1));
            } else if name == "mime" {
                if mime_seen {
                    return Err(format!("line {line_number}: duplicate [mime] section"));
                }
                mime_seen = true;
                section = Some(Section::Mime);
            } else {
                return Err(format!("line {line_number}: unknown section [{name}]"));
            }
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: expected key = value"))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(format!("line {line_number}: key and value must not be empty"));
        }

        let section = section.ok_or_else(|| {
            format!("line {line_number}: define a [server] or [site host] section first")
        })?;
        let scope = match section {
            Section::Server => "server".to_owned(),
            Section::Site(index) => format!("site:{}", config.sites[index].host),
            Section::Redirect(index) => {
                format!("redirect:{}", config.redirect_groups[index].host)
            }
            Section::Mime => "mime".to_owned(),
        };
        let key_identity = format!("{scope}:{key}");
        if !seen_keys.insert(key_identity) {
            return Err(format!("line {line_number}: duplicate key {key}"));
        }

        match section {
            Section::Server => match key {
                "address" => config.address = value.to_owned(),
                "cache_max_age_seconds" => {
                    config.cache_max_age_seconds = value.parse().map_err(|_| {
                        format!("line {line_number}: cache_max_age_seconds must be an integer")
                    })?;
                }
                "access_log" if value.eq_ignore_ascii_case("none") => {
                    config.access_log = None
                }
                "access_log" => config.access_log = Some(PathBuf::from(value)),
                "tls_cert" => config.tls_certificate = Some(PathBuf::from(value)),
                "tls_key" => config.tls_private_key = Some(PathBuf::from(value)),
                _ => return Err(format!("line {line_number}: unknown server key {key}")),
            },
            Section::Site(index) => {
                let site = &mut config.sites[index];
                match key {
                    "document_root" => site.document_root = PathBuf::from(value),
                    "index_file" => site.index_file = value.to_owned(),
                    "not_found_page" if value.eq_ignore_ascii_case("none") => {
                        site.not_found_page = None
                    }
                    "not_found_page" => site.not_found_page = Some(PathBuf::from(value)),
                    _ => return Err(format!("line {line_number}: unknown site key {key}")),
                }
            }
            Section::Redirect(index) => {
                if !key.starts_with('/') {
                    return Err(format!("line {line_number}: redirect keys must start with /"));
                }
                let (status, target) = if let Some(target) = value.strip_prefix("302 ") {
                    (302, target.trim())
                } else if let Some(target) = value.strip_prefix("301 ") {
                    (301, target.trim())
                } else {
                    (301, value)
                };
                config.redirect_groups[index]
                    .redirects
                    .push(RedirectFile {
                        path: key.to_owned(),
                        target: target.to_owned(),
                        status,
                    });
            }
            Section::Mime => {
                let extension = key.trim_start_matches('.').to_ascii_lowercase();
                if extension.is_empty()
                    || !extension
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-'))
                    || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                {
                    return Err(format!("line {line_number}: invalid MIME mapping"));
                }
                config.mime_types.insert(extension, value.to_owned());
            }
        }
    }

    if config.sites.is_empty() {
        return Err("at least one [site host] section is required".to_owned());
    }
    for site in &config.sites {
        if site.document_root.as_os_str().is_empty() {
            return Err(format!("site {} is missing document_root", site.host));
        }
    }
    Ok(config)
}

fn validate_redirect(path: &str, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['\r', '\n']) {
        return Err(format!("invalid redirect path: {path}").into());
    }
    if !(target.starts_with('/') || target.starts_with("http://") || target.starts_with("https://"))
        || target.starts_with("//")
        || target.chars().any(char::is_whitespace)
        || target.contains(['\r', '\n'])
    {
        return Err(format!("invalid redirect target: {target}").into());
    }
    Ok(())
}

fn validate_index_file(index_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    if index_file.is_empty()
        || index_file.contains('/')
        || index_file.contains('\\')
        || index_file == "."
        || index_file == ".."
    {
        return Err("index_file must be a filename within document_root".into());
    }
    Ok(())
}

fn normalize_host(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.contains(':')
        || normalized.chars().any(char::is_whitespace)
    {
        None
    } else {
        Some(normalized)
    }
}

fn handle_connection<S: Read + Write>(
    mut stream: S,
    remote: String,
    config: &Config,
) -> io::Result<()> {
    let started = Instant::now();
    let parsed_request = {
        let mut reader = BufReader::new(&mut stream);
        read_request(&mut reader)
    };
    let (method, target, headers) = match parsed_request {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return respond_bad_request(&mut stream, &remote, started, config);
        }
        Err(error) => return Err(error),
    };
    let status = serve_request(&mut stream, config, &method, &target, &headers)?;
    record_access_log(
        config,
        &format!(
            "{remote} {method} {target} {status} {}ms",
            started.elapsed().as_millis()
        ),
    );
    Ok(())
}

fn read_request<R: BufRead>(
    reader: &mut R,
) -> io::Result<Option<(String, String, HashMap<String, String>)>> {
    let mut request_line = Vec::new();
    let request_line_len = read_bounded_line(reader, &mut request_line, MAX_REQUEST_LINE_BYTES)?;
    if request_line_len == 0 {
        return Ok(None);
    }
    if !request_line.ends_with(b"\n") {
        return Err(invalid_request());
    }
    let request_line = std::str::from_utf8(&request_line).map_err(|_| invalid_request())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let target = request_parts.next().unwrap_or_default().to_owned();
    let version = request_parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || !method.bytes().all(is_http_token)
        || !target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || request_parts.next().is_some()
    {
        return Err(invalid_request());
    }

    let mut headers = HashMap::new();
    let mut header_bytes = 0;
    loop {
        let mut header = Vec::new();
        let bytes_read = read_bounded_line(reader, &mut header, MAX_HEADER_LINE_BYTES)?;
        if !header.ends_with(b"\n") {
            return Err(invalid_request());
        }
        header_bytes += bytes_read;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(invalid_request());
        }
        if header == b"\r\n" || header == b"\n" {
            break;
        }
        let header = std::str::from_utf8(&header)
            .map_err(|_| invalid_request())?
            .trim_end_matches(['\r', '\n']);
        let Some((name, value)) = header.split_once(':') else {
            return Err(invalid_request());
        };
        if name.is_empty() || !name.bytes().all(is_http_token) {
            return Err(invalid_request());
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        headers
            .entry(name)
            .and_modify(|current: &mut String| {
                current.push_str(", ");
                current.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }
    if version == "HTTP/1.1" && !headers.contains_key("host") {
        return Err(invalid_request());
    }
    Ok(Some((method, target, headers)))
}

fn invalid_request() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP request")
}

fn record_access_log(config: &Config, entry: &str) {
    println!("{entry}");
    let Some(path) = config.access_log.as_ref() else {
        return;
    };
    let mut line = entry.to_owned();
    line.push('\n');
    let result = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(line.as_bytes()));
    if let Err(error) = result {
        eprintln!("could not write access log {}: {error}", path.display());
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(line.len());
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len() + consumed > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP line exceeds configured limit",
            ));
        }
        let has_newline = available[consumed - 1] == b'\n';
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if has_newline {
            return Ok(line.len());
        }
    }
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
}

fn respond_bad_request<W: Write>(
    stream: &mut W,
    remote: &str,
    started: Instant,
    config: &Config,
) -> io::Result<()> {
    write_response(
        stream,
        400,
        "Bad Request",
        "text/plain; charset=utf-8",
        b"Bad request\n",
        false,
    )?;
    record_access_log(
        config,
        &format!("{remote} - - 400 {}ms", started.elapsed().as_millis()),
    );
    Ok(())
}

fn serve_request<W: Write>(
    stream: &mut W,
    config: &Config,
    method: &str,
    target: &str,
    headers: &HashMap<String, String>,
) -> io::Result<u16> {
    let site = select_site(config, headers);
    if method != "GET" && method != "HEAD" {
        write_response(
            stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"Method not allowed\n",
            false,
        )?;
        return Ok(405);
    }

    let path = target.split('?').next().unwrap_or_default();
    if let Some(redirect) = site.redirects.iter().find(|redirect| redirect.path == path) {
        write_redirect(stream, redirect)?;
        return Ok(redirect.status);
    }
    let Some(file_path) = resolve_file(&site.document_root, path, &site.index_file) else {
        write_response(
            stream,
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            b"Bad request\n",
            method == "HEAD",
        )?;
        return Ok(400);
    };

    match fs::canonicalize(&file_path) {
        Ok(canonical_path) if !canonical_path.starts_with(&site.document_root) => {
            send_not_found(stream, site, &config.mime_types, method == "HEAD")?;
            Ok(404)
        }
        Ok(canonical_path) => match fs::read(&canonical_path) {
            Ok(contents) => {
                if let Some(range_header) = headers.get("range") {
                    let etag = format!("\"{:016x}\"", fnv1a64(&contents));
                    let if_range_matches = headers
                        .get("if-range")
                        .is_none_or(|if_range| if_range.trim() == etag);
                    if if_range_matches {
                        if if_none_match(headers, &etag) {
                            write_not_modified(stream, &etag, config.cache_max_age_seconds)?;
                            return Ok(304);
                        }
                        if let Some((start, end)) = parse_byte_range(range_header, contents.len()) {
                            let mime_type = content_type(&canonical_path, &config.mime_types);
                            write_partial_response(
                                stream,
                                &mime_type,
                                &contents,
                                start,
                                end,
                                &etag,
                                method == "HEAD",
                                config.cache_max_age_seconds,
                            )?;
                            return Ok(206);
                        }
                        write_range_not_satisfiable(
                            stream,
                            contents.len(),
                            method == "HEAD",
                        )?;
                        return Ok(416);
                    }
                }
                let mime_type = content_type(&canonical_path, &config.mime_types);
                write_static_response(
                    stream,
                    &mime_type,
                    &contents,
                    method == "HEAD",
                    headers,
                    config.cache_max_age_seconds,
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                send_not_found(stream, site, &config.mime_types, method == "HEAD")?;
                Ok(404)
            }
            Err(error) => {
                eprintln!("could not read {}: {error}", file_path.display());
                write_response(
                    stream,
                    500,
                    "Internal Server Error",
                    "text/plain; charset=utf-8",
                    b"Internal server error\n",
                    method == "HEAD",
                )?;
                Ok(500)
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            send_not_found(stream, site, &config.mime_types, method == "HEAD")?;
            Ok(404)
        }
        Err(error) => Err(error),
    }
}

fn parse_byte_range(value: &str, length: usize) -> Option<(usize, usize)> {
    if length == 0 {
        return None;
    }
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    if start.is_empty() {
        let suffix_length = end.parse::<usize>().ok()?;
        if suffix_length == 0 {
            return None;
        }
        return Some((length.saturating_sub(suffix_length), length - 1));
    }

    let start = start.parse::<usize>().ok()?;
    if start >= length {
        return None;
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<usize>().ok()?.min(length - 1)
    };
    (start <= end).then_some((start, end))
}

fn select_site<'a>(config: &'a Config, headers: &HashMap<String, String>) -> &'a Site {
    let host = headers.get("host").and_then(|value| request_host(value));
    host.and_then(|host| config.sites.iter().find(|site| site.host == host))
        .unwrap_or(&config.sites[0])
}

fn request_host(authority: &str) -> Option<String> {
    let authority = authority.trim();
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']')?;
        &bracketed[..end]
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            host
        } else {
            authority
        }
    } else {
        authority
    };
    normalize_host(host)
}

fn send_not_found<W: Write>(
    stream: &mut W,
    site: &Site,
    mime_types: &HashMap<String, String>,
    head_only: bool,
) -> io::Result<()> {
    if let Some(page) = site.not_found_page.as_deref() {
        if let Some(path) = resolve_configured_page(&site.document_root, page) {
            if let Ok(contents) = fs::read(&path) {
                let mime_type = content_type(&path, mime_types);
                return write_response(
                    stream,
                    404,
                    "Not Found",
                    &mime_type,
                    &contents,
                    head_only,
                );
            }
        }
    }

    write_response(
        stream,
        404,
        "Not Found",
        "text/plain; charset=utf-8",
        b"Not found\n",
        head_only,
    )
}

fn resolve_configured_page(root: &Path, page: &Path) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for component in page.components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    let canonical = fs::canonicalize(path).ok()?;
    canonical.starts_with(root).then_some(canonical)
}

fn resolve_file(root: &Path, request_path: &str, index_file: &str) -> Option<PathBuf> {
    if !request_path.starts_with('/') || request_path.contains('\\') {
        return None;
    }

    let relative_path = request_path.trim_start_matches('/');
    let mut path = root.to_path_buf();
    for component in Path::new(relative_path).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }

    if request_path.ends_with('/') || path.is_dir() {
        path.push(index_file);
    }
    Some(path)
}

fn content_type(path: &Path, custom_mime_types: &HashMap<String, String>) -> String {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if let Some(mime_type) = custom_mime_types.get(&extension) {
        return mime_type.clone();
    }
    match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
    .to_owned()
}

fn write_response<W: Write>(
    stream: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn write_redirect<W: Write>(stream: &mut W, redirect: &Redirect) -> io::Result<()> {
    let reason = match redirect.status {
        302 => "Found",
        _ => "Moved Permanently",
    };
    write!(
        stream,
        "HTTP/1.1 {} {reason}\r\nLocation: {}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        redirect.status, redirect.target
    )?;
    stream.flush()
}

fn write_partial_response<W: Write>(
    stream: &mut W,
    mime_type: &str,
    body: &[u8],
    start: usize,
    end: usize,
    etag: &str,
    head_only: bool,
    max_age_seconds: u64,
) -> io::Result<()> {
    let partial = &body[start..=end];
    write!(
        stream,
        "HTTP/1.1 206 Partial Content\r\nContent-Type: {mime_type}\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nAccept-Ranges: bytes\r\nETag: {etag}\r\nCache-Control: public, max-age={max_age_seconds}\r\nConnection: close\r\n\r\n",
        partial.len(),
        body.len()
    )?;
    if !head_only {
        stream.write_all(partial)?;
    }
    stream.flush()
}

fn write_range_not_satisfiable<W: Write>(
    stream: &mut W,
    length: usize,
    head_only: bool,
) -> io::Result<()> {
    let body = b"Range not satisfiable\n";
    write!(
        stream,
        "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{length}\r\nAccept-Ranges: bytes\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn write_static_response<W: Write>(
    stream: &mut W,
    mime_type: &str,
    body: &[u8],
    head_only: bool,
    headers: &HashMap<String, String>,
    max_age_seconds: u64,
) -> io::Result<u16> {
    let compressed = if body.len() >= 256
        && is_compressible(mime_type)
        && accepts_gzip(headers)
    {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body)?;
        let encoded = encoder.finish()?;
        (encoded.len() < body.len()).then_some(encoded)
    } else {
        None
    };
    let (representation, encoding) = match compressed.as_deref() {
        Some(encoded) => (encoded, Some("gzip")),
        None => (body, None),
    };
    let etag = format!("\"{:016x}\"", fnv1a64(representation));
    if if_none_match(headers, &etag) {
        write_not_modified(stream, &etag, max_age_seconds)?;
        return Ok(304);
    }

    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {mime_type}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nETag: {etag}\r\nCache-Control: public, max-age={max_age_seconds}\r\nVary: Accept-Encoding\r\n",
        representation.len()
    )?;
    if let Some(encoding) = encoding {
        write!(stream, "Content-Encoding: {encoding}\r\n")?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    if !head_only {
        stream.write_all(representation)?;
    }
    stream.flush()?;
    Ok(200)
}

fn write_not_modified<W: Write>(
    stream: &mut W,
    etag: &str,
    max_age_seconds: u64,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nCache-Control: public, max-age={max_age_seconds}\r\nVary: Accept-Encoding\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()
}

fn accepts_gzip(headers: &HashMap<String, String>) -> bool {
    let Some(value) = headers.get("accept-encoding") else {
        return false;
    };
    let mut wildcard = false;
    for item in value.split(',') {
        let mut parts = item.trim().split(';');
        let coding = parts.next().unwrap_or_default().trim();
        let quality = parts
            .filter_map(|parameter| parameter.trim().strip_prefix("q="))
            .next()
            .and_then(|quality| quality.parse::<f32>().ok())
            .unwrap_or(1.0);
        if coding.eq_ignore_ascii_case("gzip") {
            return quality > 0.0;
        }
        if coding == "*" {
            wildcard = quality > 0.0;
        }
    }
    wildcard
}

fn is_compressible(mime_type: &str) -> bool {
    mime_type.starts_with("text/")
        || mime_type.starts_with("application/json")
        || mime_type.starts_with("application/javascript")
        || mime_type == "image/svg+xml"
}

fn if_none_match(headers: &HashMap<String, String>, etag: &str) -> bool {
    headers
        .get("if-none-match")
        .is_some_and(|value| value.split(',').any(|candidate| {
            let candidate = candidate.trim();
            candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
        }))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
