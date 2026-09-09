use crate::models::DnsRecord;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use std::sync::Arc;

#[derive(Clone)]
pub struct AsyncDnsResolver {
    resolver: Arc<TokioAsyncResolver>,
}

impl AsyncDnsResolver {
    pub fn new() -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Self {
            resolver: Arc::new(resolver),
        }
    }

    pub async fn resolve_all(&self, hostname: &str) -> Vec<DnsRecord> {
        let mut records = Vec::new();

        // 1. Resolve A records (IPv4)
        if let Ok(lookup) = self.resolver.ipv4_lookup(hostname).await {
            for ip in lookup.iter() {
                records.push(DnsRecord::new(
                    hostname.to_string(),
                    "A".to_string(),
                    ip.to_string(),
                    Some(300),
                ));
            }
        }

        // 2. Resolve AAAA records (IPv6)
        if let Ok(lookup) = self.resolver.ipv6_lookup(hostname).await {
            for ip in lookup.iter() {
                records.push(DnsRecord::new(
                    hostname.to_string(),
                    "AAAA".to_string(),
                    ip.to_string(),
                    Some(300),
                ));
            }
        }

        // 3. Resolve CNAME records using generic lookup
        if let Ok(lookup) = self.resolver.lookup(hostname, RecordType::CNAME).await {
            for record in lookup.iter() {
                if let Some(cname) = record.as_cname() {
                    records.push(DnsRecord::new(
                        hostname.to_string(),
                        "CNAME".to_string(),
                        cname.to_string().trim_end_matches('.').to_string(),
                        Some(300),
                    ));
                }
            }
        }

        // 4. Resolve MX records using generic lookup
        if let Ok(lookup) = self.resolver.lookup(hostname, RecordType::MX).await {
            for record in lookup.iter() {
                if let Some(mx) = record.as_mx() {
                    records.push(DnsRecord::new(
                        hostname.to_string(),
                        "MX".to_string(),
                        mx.exchange().to_string().trim_end_matches('.').to_string(),
                        Some(300),
                    ));
                }
            }
        }

        // Fallback to tokio lookup if hickory returned no A/AAAA records
        if records.is_empty() {
            let addr_str = format!("{}:80", hostname);
            if let Ok(mut addrs) = tokio::net::lookup_host(&addr_str).await {
                if let Some(addr) = addrs.next() {
                    let rec_type = if addr.ip().is_ipv6() { "AAAA" } else { "A" };
                    records.push(DnsRecord::new(
                        hostname.to_string(),
                        rec_type.to_string(),
                        addr.ip().to_string(),
                        Some(300),
                    ));
                }
            }
        }

        records
    }

    pub async fn is_wildcard_domain(&self, domain: &str) -> bool {
        let random_prefix = format!("_wildcard_{}", uuid::Uuid::new_v4().simple());
        let probe_target = format!("{}.{}", random_prefix, domain.trim_start_matches("www."));

        if let Ok(lookup) = self.resolver.ipv4_lookup(&probe_target).await {
            if lookup.iter().next().is_some() {
                return true;
            }
        }

        if let Ok(lookup) = self.resolver.ipv6_lookup(&probe_target).await {
            if lookup.iter().next().is_some() {
                return true;
            }
        }

        false
    }
}
