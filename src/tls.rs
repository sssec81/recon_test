use native_tls::TlsConnector;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct TlsCertificateInfo {
    pub issuer: String,
    pub expires_at: Option<String>,
    pub san_domains: Vec<String>,
}

/// Fetches TLS certificate metadata and Subject Alternative Names (SANs) for a given host:port.
///
/// Note: Uses `danger_accept_invalid_certs(true)` because bug bounty target endpoints
/// often present self-signed, expired, or staging TLS certificates whose SAN domains
/// are still valuable for attack surface discovery.
pub fn fetch_tls_info(hostname: &str, port: u16) -> Option<TlsCertificateInfo> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    let addr_str = format!("{}:{}", hostname, port);
    let socket_addr = addr_str.to_socket_addrs().ok()?.next()?;

    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

    let tls_stream = connector.connect(hostname, stream).ok()?;
    let cert = tls_stream.peer_certificate().ok()??;
    let der = cert.to_der().ok()?;

    let (_, parsed_cert) = parse_x509_certificate(&der).ok()?;

    let issuer = parsed_cert.issuer().to_string();
    let expires_at = Some(parsed_cert.validity().not_after.to_string());

    let mut san_domains = Vec::new();

    // Iterate over X.509 extensions to find Subject Alternative Name (SAN)
    for ext in parsed_cert.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::DNSName(dns) = name {
                        let clean = dns.trim().to_lowercase();
                        let clean_no_wild = clean.trim_start_matches("*.").to_string();
                        if !clean_no_wild.is_empty() {
                            san_domains.push(clean_no_wild);
                        }
                    }
                }
            }
        }
    }

    Some(TlsCertificateInfo {
        issuer,
        expires_at,
        san_domains,
    })
}
