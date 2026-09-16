use crate::scan::pipeline::ReconEvent;
use crate::storage::db::ObservationBundle;
use crate::storage::models::Hostname;
use std::collections::HashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

pub async fn process_events(
    mut events: mpsc::Receiver<ReconEvent>,
    db_channel: mpsc::Sender<ObservationBundle>,
    scan_id: Uuid,
) -> Result<(), String> {
    let mut pending: HashMap<String, ObservationBundle> = HashMap::new();
    while let Some(event) = events.recv().await {
        match event {
            ReconEvent::HostnameDiscovered { hostname, source } => {
                let name = hostname.as_str().to_string();
                pending.insert(
                    name.clone(),
                    ObservationBundle {
                        scan_id,
                        hostname: Hostname::new(name, source, None),
                        dns_records: Vec::new(),
                        services: Vec::new(),
                        tls_records: Vec::new(),
                        technologies: Vec::new(),
                        http_observations: Vec::new(),
                    },
                );
            }
            ReconEvent::DnsResolved { hostname, records } => {
                if let Some(bundle) = pending.get_mut(hostname.as_str()) {
                    bundle.dns_records.extend(records);
                }
            }
            ReconEvent::ServiceObserved { hostname, services } => {
                if let Some(bundle) = pending.get_mut(hostname.as_str()) {
                    bundle.services.extend(services);
                }
            }
            ReconEvent::TlsObserved {
                hostname,
                tls_record,
            } => {
                if let Some(bundle) = pending.get_mut(hostname.as_str()) {
                    bundle.tls_records.push(tls_record);
                }
            }
            ReconEvent::TechnologyDetected {
                hostname,
                technologies,
            } => {
                if let Some(bundle) = pending.get_mut(hostname.as_str()) {
                    bundle.technologies.extend(technologies);
                }
            }
            ReconEvent::HttpObserved(obs) => {
                let status = obs
                    .status_code
                    .map_or_else(|| "ERR".to_string(), |s| s.to_string());
                println!(
                    "  [{status:<3}] {:<48} | RTT: {:?}ms | Server: {} | Title: {}",
                    obs.url,
                    obs.rtt_ms,
                    obs.server_header.as_deref().unwrap_or("Unknown"),
                    obs.title.as_deref().unwrap_or("No Title")
                );
                let bundle = pending.get_mut(&obs.hostname).ok_or_else(|| {
                    format!("observation without hostname event: {}", obs.hostname)
                })?;
                bundle.http_observations.push(obs);
            }
            ReconEvent::TargetFinished { hostname } => {
                let bundle = pending
                    .remove(hostname.as_str())
                    .ok_or_else(|| format!("completion without hostname event: {hostname}"))?;
                db_channel
                    .send(bundle)
                    .await
                    .map_err(|_| "database writer channel closed".to_string())?;
            }
        }
    }
    if !pending.is_empty() {
        return Err(format!("{} target(s) did not finish", pending.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::normalize::NormalizedHostname;
    use crate::storage::models::{DiscoverySource, HttpObservation};

    #[tokio::test]
    async fn flushes_after_completion_with_all_endpoints() {
        let (event_tx, event_rx) = mpsc::channel(8);
        let (db_tx, mut db_rx) = mpsc::channel(1);
        let scan_id = Uuid::new_v4();
        let task = tokio::spawn(process_events(event_rx, db_tx, scan_id));
        let hostname = NormalizedHostname::new("example.com").unwrap();
        event_tx
            .send(ReconEvent::HostnameDiscovered {
                hostname: hostname.clone(),
                source: DiscoverySource::Seed,
            })
            .await
            .unwrap();
        for url in ["http://example.com", "https://example.com"] {
            event_tx
                .send(ReconEvent::HttpObserved(HttpObservation::new(
                    scan_id,
                    "example.com".into(),
                    url.into(),
                )))
                .await
                .unwrap();
        }
        assert!(db_rx.try_recv().is_err());
        event_tx
            .send(ReconEvent::TargetFinished { hostname })
            .await
            .unwrap();
        drop(event_tx);
        let bundle = db_rx.recv().await.unwrap();
        assert_eq!(bundle.http_observations.len(), 2);
        assert!(task.await.unwrap().is_ok());
    }
}
