use std::{collections::HashMap, path::PathBuf, time::Duration};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
pub const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
pub const MAX_HEADER_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub struct ConfigFile {
    pub address: String,
    pub cache_max_age_seconds: u64,
    pub access_log: Option<PathBuf>,
    pub tls_certificate: Option<PathBuf>,
    pub tls_private_key: Option<PathBuf>,
    pub sites: Vec<SiteFile>,
    pub redirect_groups: Vec<RedirectGroup>,
    pub mime_types: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SiteFile {
    pub host: String,
    pub document_root: PathBuf,
    pub index_file: String,
    pub not_found_page: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Site {
    pub host: String,
    pub document_root: PathBuf,
    pub index_file: String,
    pub not_found_page: Option<PathBuf>,
    pub redirects: Vec<Redirect>,
}

#[derive(Debug, Clone)]
pub struct RedirectGroup {
    pub host: String,
    pub redirects: Vec<RedirectFile>,
}

#[derive(Debug, Clone)]
pub struct RedirectFile {
    pub path: String,
    pub target: String,
    pub status: u16,
}

#[derive(Debug, Clone)]
pub struct Redirect {
    pub path: String,
    pub target: String,
    pub status: u16,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub address: String,
    pub cache_max_age_seconds: u64,
    pub access_log: Option<PathBuf>,
    pub tls: Option<TlsPaths>,
    pub sites: Vec<Site>,
    pub mime_types: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
