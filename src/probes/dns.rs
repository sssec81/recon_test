use crate::storage::models::DnsRecord;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AsyncDnsResolver {
    resolver: Arc<TokioAsyncResolver>,
}

impl AsyncDnsResolver {
    pub fn new() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Self {
            resolver: Arc::new(resolver),
        }
    }

    pub async fn resolve_all(&self, scan_id: Uuid, hostname: &str) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            let kind = if ip.is_ipv4() { "A" } else { "AAAA" };
            return vec![DnsRecord::new(
                scan_id,
                hostname.to_string(),
                kind.to_string(),
                ip.to_string(),
                None,
            )];
        }

        // 1. Resolve A records (IPv4)
        if let Ok(lookup) = self.resolver.ipv4_lookup(hostname).await {
            for ip in lookup.iter() {
                records.push(DnsRecord::new(
                    scan_id,
                    hostname.to_string(),
                    "A".to_string(),
                    ip.to_string(),
                    None,
                ));
            }
        }

        // 2. Resolve AAAA records (IPv6)
        if let Ok(lookup) = self.resolver.ipv6_lookup(hostname).await {
            for ip in lookup.iter() {
                records.push(DnsRecord::new(
                    scan_id,
                    hostname.to_string(),
                    "AAAA".to_string(),
                    ip.to_string(),
                    None,
                ));
            }
        }

        // 3. Resolve CNAME records using generic lookup
        if let Ok(lookup) = self.resolver.lookup(hostname, RecordType::CNAME).await {
            for record in lookup.iter() {
                if let Some(cname) = record.as_cname() {
                    records.push(DnsRecord::new(
                        scan_id,
                        hostname.to_string(),
                        "CNAME".to_string(),
                        cname.to_string().trim_end_matches('.').to_string(),
                        None,
                    ));
                }
            }
        }

        // 4. Resolve MX records using generic lookup
        if let Ok(lookup) = self.resolver.lookup(hostname, RecordType::MX).await {
            for record in lookup.iter() {
                if let Some(mx) = record.as_mx() {
                    records.push(DnsRecord::new(
                        scan_id,
                        hostname.to_string(),
                        "MX".to_string(),
                        mx.exchange().to_string().trim_end_matches('.').to_string(),
                        None,
                    ));
                }
            }
        }

        // Fallback to tokio lookup if hickory returned no A/AAAA records
        if !records
            .iter()
            .any(|r| r.record_type == "A" || r.record_type == "AAAA")
        {
            let addr_str = format!("{}:80", hostname);
            if let Ok(mut addrs) = tokio::net::lookup_host(&addr_str).await
                && let Some(addr) = addrs.next()
            {
                let rec_type = if addr.ip().is_ipv6() { "AAAA" } else { "A" };
                records.push(DnsRecord::new(
                    scan_id,
                    hostname.to_string(),
                    rec_type.to_string(),
                    addr.ip().to_string(),
                    None,
                ));
            }
        }

        records
    }

    pub async fn wildcard_ips(&self, domain: &str) -> HashSet<String> {
        let mut samples = Vec::new();
        for _ in 0..2 {
            let probe = format!("wildcard-{}.{}", uuid::Uuid::new_v4().simple(), domain);
            let records = self.resolve_all(Uuid::nil(), &probe).await;
            let ips: HashSet<String> = records
                .into_iter()
                .filter(|r| r.record_type == "A" || r.record_type == "AAAA")
                .map(|r| r.value)
                .collect();
            samples.push(ips);
        }
        if samples[0].is_empty() || samples[0] != samples[1] {
            HashSet::new()
        } else {
            samples.remove(0)
        }
    }
}
