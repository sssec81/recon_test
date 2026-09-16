use crate::probes::dns::AsyncDnsResolver;
use crate::probes::fingerprint;
use crate::probes::{scanner, services, tls};
use crate::scan::pipeline::{ReconEvent, Scheduler, WorkItem};
use crate::storage::models::{
    DiscoverySource, HttpObservation, ServiceRecord, TechnologyObservation, TlsRecord,
};
use scanner::SchemeStrategy;
use tokio::sync::mpsc;
use uuid::Uuid;

pub async fn probe(
    work: WorkItem,
    client: reqwest::Client,
    resolver: AsyncDnsResolver,
    strategy: SchemeStrategy,
    scan_id: Uuid,
    bus: mpsc::Sender<ReconEvent>,
    worker_scheduler: Scheduler,
) {
    match work {
        WorkItem::ProbeTarget { hostname, source } => {
            // Emit HostnameDiscovered event
            let _ = bus
                .send(ReconEvent::HostnameDiscovered {
                    hostname: hostname.clone(),
                    source,
                })
                .await;

            // Resolve multi-record DNS
            let dns_records = resolver.resolve_all(scan_id, hostname.as_str()).await;
            let _ = bus
                .send(ReconEvent::DnsResolved {
                    hostname: hostname.clone(),
                    records: dns_records,
                })
                .await;

            // Perform TCP Port Scan on default web ports
            let open_ports =
                services::probe_open_ports(hostname.as_str(), services::DEFAULT_PORTS).await;
            let service_records: Vec<ServiceRecord> = open_ports
                .iter()
                .map(|&port| {
                    ServiceRecord::new(hostname.as_str().to_string(), port, "tcp".to_string(), true)
                })
                .collect();

            let _ = bus
                .send(ReconEvent::ServiceObserved {
                    hostname: hostname.clone(),
                    services: service_records,
                })
                .await;

            // Fetch TLS Certificate & SANs if port 443 or 8443 is open
            if open_ports.contains(&443) || open_ports.contains(&8443) {
                let tls_port = if open_ports.contains(&443) { 443 } else { 8443 };
                let host_str = hostname.as_str().to_string();
                let tls_info_opt =
                    tokio::task::spawn_blocking(move || tls::fetch_tls_info(&host_str, tls_port))
                        .await
                        .ok()
                        .flatten();

                if let Some(tls_info) = tls_info_opt {
                    // TLS SAN Feedback Loop: submit SAN subdomains directly in active worker
                    for san_domain in &tls_info.san_domains {
                        worker_scheduler
                            .submit_target_with_source(san_domain, DiscoverySource::TlsSan)
                            .await;
                    }

                    let service_id = format!("{}:{}:tcp", hostname.as_str(), tls_port);
                    let tls_rec = TlsRecord::new(
                        service_id,
                        tls_info.issuer,
                        tls_info.san_domains,
                        tls_info.expires_at,
                    );

                    let _ = bus
                        .send(ReconEvent::TlsObserved {
                            hostname: hostname.clone(),
                            tls_record: tls_rec,
                        })
                        .await;
                }
            }

            // Perform HTTP Probe
            let scan = scanner::probe_subdomain(&client, hostname.as_str(), strategy).await;

            // Winning URL Scheme propagation
            let url = scan
                .final_url
                .clone()
                .unwrap_or_else(|| format!("https://{}", hostname.as_str()));

            let status = scan.status_code.unwrap_or(0);
            let raw_detections =
                fingerprint::fingerprint_tech(&scan.headers, &scan.body_snippet, status);

            let tech_observations: Vec<TechnologyObservation> = raw_detections
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

            if !tech_observations.is_empty() {
                let _ = bus
                    .send(ReconEvent::TechnologyDetected {
                        hostname: hostname.clone(),
                        technologies: tech_observations,
                    })
                    .await;
            }

            let http_obs = HttpObservation::new(scan_id, hostname.as_str().to_string(), url)
                .with_response(scan.status_code, scan.title, scan.server, scan.rtt_ms, None);

            let _ = bus.send(ReconEvent::HttpObserved(http_obs)).await;
        }
    }
}
