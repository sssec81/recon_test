use crate::probes::dns::AsyncDnsResolver;
use crate::probes::fingerprint;
use crate::probes::{scanner, services, tls};
use crate::scan::pipeline::{ReconEvent, Scheduler, WorkItem};
use crate::storage::models::{
    DiscoverySource, HttpObservation, ServiceRecord, TechnologyObservation, TlsRecord,
};
use scanner::SchemeStrategy;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct WorkerContext {
    pub client: reqwest::Client,
    pub resolver: AsyncDnsResolver,
    pub strategy: SchemeStrategy,
    pub scan_id: Uuid,
    pub bus: mpsc::Sender<ReconEvent>,
    pub scheduler: Scheduler,
    pub wildcard_ips: Arc<HashMap<String, HashSet<String>>>,
}

pub async fn probe(work: WorkItem, context: WorkerContext) -> Result<(), String> {
    let WorkerContext {
        client,
        resolver,
        strategy,
        scan_id,
        bus,
        scheduler,
        wildcard_ips,
    } = context;
    let WorkItem::ProbeTarget { hostname, source } = work;
    let name = hostname.as_str().to_string();
    let host = hostname.as_url_host();
    let records = resolver.resolve_all(scan_id, &name).await;
    if source == DiscoverySource::DnsBruteforce
        && is_wildcard_candidate(&name, &records, &wildcard_ips)
    {
        return Ok(());
    }
    bus.send(ReconEvent::HostnameDiscovered {
        hostname: hostname.clone(),
        source,
    })
    .await
    .map_err(|_| "event channel closed".to_string())?;

    bus.send(ReconEvent::DnsResolved {
        hostname: hostname.clone(),
        records,
    })
    .await
    .map_err(|_| "event channel closed".to_string())?;

    let open_ports = services::probe_open_ports(&host, services::DEFAULT_PORTS).await;
    let service_records = open_ports
        .iter()
        .map(|&port| ServiceRecord::new(scan_id, name.clone(), port, "tcp".to_string(), true))
        .collect();
    bus.send(ReconEvent::ServiceObserved {
        hostname: hostname.clone(),
        services: service_records,
    })
    .await
    .map_err(|_| "event channel closed".to_string())?;

    for port in open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 443 | 8443))
    {
        let tls_host = name.clone();
        let tls_info = tokio::task::spawn_blocking(move || tls::fetch_tls_info(&tls_host, port))
            .await
            .map_err(|e| e.to_string())?;
        if let Some(info) = tls_info {
            for san in &info.san_domains {
                scheduler
                    .submit_target_with_source(san, DiscoverySource::TlsSan)
                    .await;
            }
            let service_id = format!("{scan_id}:{name}:{port}:tcp");
            let record = TlsRecord::new(
                scan_id,
                service_id,
                info.issuer,
                info.san_domains,
                info.expires_at,
            );
            bus.send(ReconEvent::TlsObserved {
                hostname: hostname.clone(),
                tls_record: record,
            })
            .await
            .map_err(|_| "event channel closed".to_string())?;
        }
    }

    let endpoints = endpoint_candidates(&host, &open_ports, strategy);
    if endpoints.is_empty() {
        for (url, result) in scanner::probe_subdomain(&client, &host, strategy).await {
            emit_http(scan_id, &name, url, result, &bus).await?;
        }
    } else if strategy == SchemeStrategy::BothParallel {
        let results = futures_util::future::join_all(
            endpoints
                .iter()
                .map(|endpoint| probe_endpoint(&client, endpoint, strategy)),
        )
        .await;
        for (url, result) in results {
            emit_http(scan_id, &name, url, result, &bus).await?;
        }
    } else {
        for endpoint in endpoints {
            let (url, result) = probe_endpoint(&client, &endpoint, strategy).await;
            emit_http(scan_id, &name, url, result, &bus).await?;
        }
    }
    bus.send(ReconEvent::TargetFinished { hostname })
        .await
        .map_err(|_| "event channel closed".to_string())?;
    Ok(())
}

fn endpoint_candidates(host: &str, open_ports: &[u16], strategy: SchemeStrategy) -> Vec<String> {
    let mut endpoints = Vec::new();
    for port in open_ports {
        match port {
            80 if strategy != SchemeStrategy::HttpsOnly => endpoints.push(format!("http://{host}")),
            443 => endpoints.push(format!("https://{host}")),
            8000 | 8080 | 8443 => {
                endpoints.push(format!("https://{host}:{port}"));
                if strategy == SchemeStrategy::BothParallel {
                    endpoints.push(format!("http://{host}:{port}"));
                }
            }
            _ => {}
        }
    }
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

async fn probe_endpoint(
    client: &reqwest::Client,
    endpoint: &str,
    strategy: SchemeStrategy,
) -> (String, scanner::ScanResult) {
    if let Some(result) = scanner::probe_single_url(client, endpoint).await {
        return (endpoint.to_string(), result);
    }
    if strategy == SchemeStrategy::HttpsFirst
        && endpoint.starts_with("https://")
        && reqwest::Url::parse(endpoint)
            .ok()
            .and_then(|url| url.port())
            .is_some()
    {
        // Alternate ports may serve plaintext HTTP despite their conventional scheme.
        let url = endpoint.replacen("https://", "http://", 1);
        if let Some(result) = scanner::probe_single_url(client, &url).await {
            return (url, result);
        }
    }
    (endpoint.to_string(), scanner::ScanResult::default())
}

fn is_wildcard_candidate(
    name: &str,
    records: &[crate::storage::models::DnsRecord],
    wildcard_ips: &HashMap<String, HashSet<String>>,
) -> bool {
    let addresses: HashSet<&str> = records
        .iter()
        .filter(|r| r.record_type == "A" || r.record_type == "AAAA")
        .map(|r| r.value.as_str())
        .collect();
    wildcard_ips.iter().any(|(root, ips)| {
        (name == root || name.ends_with(&format!(".{root}")))
            && !ips.is_empty()
            && addresses == ips.iter().map(String::as_str).collect()
    })
}

async fn emit_http(
    scan_id: Uuid,
    hostname: &str,
    url: String,
    result: scanner::ScanResult,
    bus: &mpsc::Sender<ReconEvent>,
) -> Result<(), String> {
    let technologies: Vec<TechnologyObservation> = fingerprint::fingerprint_tech(
        &result.headers,
        &result.body_snippet,
        result.status_code.unwrap_or(0),
    )
    .into_iter()
    .map(|d| {
        TechnologyObservation::new(
            scan_id,
            url.clone(),
            d.name,
            d.version,
            d.confidence,
            d.evidence,
        )
    })
    .collect();
    if !technologies.is_empty() {
        let hostname = crate::scan::normalize::NormalizedHostname::new(hostname)
            .ok_or_else(|| "invalid normalized hostname".to_string())?;
        bus.send(ReconEvent::TechnologyDetected {
            hostname,
            technologies,
        })
        .await
        .map_err(|_| "event channel closed".to_string())?;
    }
    let obs = HttpObservation::new(scan_id, hostname.to_string(), url).with_response(
        result.status_code,
        result.title,
        result.server,
        result.rtt_ms,
        None,
    );
    bus.send(ReconEvent::HttpObserved(obs))
        .await
        .map_err(|_| "event channel closed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probes_each_open_web_endpoint() {
        let urls = endpoint_candidates(
            "example.com",
            &[80, 443, 8080, 8443],
            SchemeStrategy::HttpsFirst,
        );
        assert_eq!(
            urls,
            [
                "http://example.com",
                "https://example.com",
                "https://example.com:8080",
                "https://example.com:8443"
            ]
        );
        let only_https = endpoint_candidates(
            "example.com",
            &[80, 443, 8080, 8443],
            SchemeStrategy::HttpsOnly,
        );
        assert_eq!(
            only_https,
            [
                "https://example.com",
                "https://example.com:8080",
                "https://example.com:8443"
            ]
        );
        let parallel =
            endpoint_candidates("example.com", &[8080, 8443], SchemeStrategy::BothParallel);
        assert_eq!(
            parallel,
            [
                "http://example.com:8080",
                "http://example.com:8443",
                "https://example.com:8080",
                "https://example.com:8443"
            ]
        );
    }

    #[test]
    fn identifies_wildcard_dns_answers_for_generated_names() {
        let scan = Uuid::new_v4();
        let records = vec![crate::storage::models::DnsRecord::new(
            scan,
            "random.example.com".into(),
            "A".into(),
            "192.0.2.1".into(),
            None,
        )];
        let wildcards = HashMap::from([(
            "example.com".to_string(),
            HashSet::from(["192.0.2.1".to_string()]),
        )]);
        assert!(is_wildcard_candidate(
            "random.example.com",
            &records,
            &wildcards
        ));
        assert!(!is_wildcard_candidate(
            "random.other.com",
            &records,
            &wildcards
        ));
    }
}
