use crate::scan::pipeline::ReconEvent;
use crate::storage::db::ObservationBundle;
use crate::storage::models::{DiscoverySource, Hostname, HttpObservation};
use tokio::sync::mpsc;
use uuid::Uuid;

pub async fn process_events(
    mut event_rx: mpsc::Receiver<ReconEvent>,
    db_channel: mpsc::Sender<ObservationBundle>,
    scan_id: Uuid,
) {
    let mut pending_bundles: std::collections::HashMap<String, ObservationBundle> =
        std::collections::HashMap::new();

    while let Some(event) = event_rx.recv().await {
        match event {
            ReconEvent::HostnameDiscovered { hostname, source } => {
                let name = hostname.as_str().to_string();
                let host_entity = Hostname::new(name.clone(), source, None);
                let dummy_http =
                    HttpObservation::new(scan_id, name.clone(), format!("https://{}", name));
                pending_bundles.insert(
                    name,
                    ObservationBundle {
                        hostname: host_entity,
                        dns_records: Vec::new(),
                        services: Vec::new(),
                        tls_record: None,
                        technologies: Vec::new(),
                        http_observation: dummy_http,
                    },
                );
            }
            ReconEvent::DnsResolved { hostname, records } => {
                let name = hostname.as_str().to_string();
                if let Some(bundle) = pending_bundles.get_mut(&name) {
                    bundle.dns_records.extend(records);
                }
            }
            ReconEvent::ServiceObserved { hostname, services } => {
                let name = hostname.as_str().to_string();
                if let Some(bundle) = pending_bundles.get_mut(&name) {
                    bundle.services.extend(services);
                }
            }
            ReconEvent::TlsObserved {
                hostname,
                tls_record,
            } => {
                let name = hostname.as_str().to_string();
                if let Some(bundle) = pending_bundles.get_mut(&name) {
                    bundle.tls_record = Some(tls_record);
                }
            }
            ReconEvent::TechnologyDetected {
                hostname,
                technologies,
            } => {
                let name = hostname.as_str().to_string();
                if let Some(bundle) = pending_bundles.get_mut(&name) {
                    bundle.technologies.extend(technologies);
                }
            }
            ReconEvent::HttpObserved(obs) => {
                let status_str = obs
                    .status_code
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "ERR".to_string());
                let title_str = obs.title.as_deref().unwrap_or("No Title");
                let server_str = obs.server_header.as_deref().unwrap_or("Unknown Server");
                let rtt_str = obs
                    .rtt_ms
                    .map(|r| format!("{}ms", r))
                    .unwrap_or_else(|| "N/A".to_string());

                let name = obs.hostname.clone();
                let tech_summary = if let Some(bundle) = pending_bundles.get(&name) {
                    if !bundle.technologies.is_empty() {
                        let tech_names: Vec<String> = bundle
                            .technologies
                            .iter()
                            .map(|t| format!("{} ({}%)", t.name, (t.confidence * 100.0) as u32))
                            .collect();
                        format!(" | Tech: {}", tech_names.join(", "))
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                println!(
                    "  [{:<3}] {:<32} | RTT: {:<6} | Server: {:<12} | Title: {}{}",
                    status_str, obs.hostname, rtt_str, server_str, title_str, tech_summary
                );

                if let Some(mut bundle) = pending_bundles.remove(&name) {
                    bundle.http_observation = obs;
                    let _ = db_channel.send(bundle).await;
                } else {
                    let host_entity = Hostname::new(name.clone(), DiscoverySource::Seed, None);
                    let bundle = ObservationBundle {
                        hostname: host_entity,
                        dns_records: Vec::new(),
                        services: Vec::new(),
                        tls_record: None,
                        technologies: Vec::new(),
                        http_observation: obs,
                    };
                    let _ = db_channel.send(bundle).await;
                }
            }
        }
    }
}
