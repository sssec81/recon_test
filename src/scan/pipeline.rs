use crate::scan::normalize::NormalizedHostname;
use crate::scan::scope::ScopePolicy;
use crate::storage::models::{
    DiscoverySource, DnsRecord, HttpObservation, ServiceRecord, TechnologyObservation, TlsRecord,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum WorkItem {
    ProbeTarget {
        hostname: NormalizedHostname,
        source: DiscoverySource,
    },
}

#[derive(Debug, Clone)]
pub enum ReconEvent {
    HostnameDiscovered {
        hostname: NormalizedHostname,
        source: DiscoverySource,
    },
    DnsResolved {
        hostname: NormalizedHostname,
        records: Vec<DnsRecord>,
    },
    ServiceObserved {
        hostname: NormalizedHostname,
        services: Vec<ServiceRecord>,
    },
    TlsObserved {
        hostname: NormalizedHostname,
        tls_record: TlsRecord,
    },
    TechnologyDetected {
        hostname: NormalizedHostname,
        technologies: Vec<TechnologyObservation>,
    },
    HttpObserved(HttpObservation),
    TargetFinished {
        hostname: NormalizedHostname,
    },
}

#[derive(Clone)]
pub struct Scheduler {
    scope: ScopePolicy,
    seen_hostnames: Arc<Mutex<HashSet<NormalizedHostname>>>,
    work_tx: mpsc::UnboundedSender<WorkItem>,
}

impl Scheduler {
    pub fn new(scope: ScopePolicy, work_tx: mpsc::UnboundedSender<WorkItem>) -> Self {
        Self {
            scope,
            seen_hostnames: Arc::new(Mutex::new(HashSet::new())),
            work_tx,
        }
    }

    pub async fn submit_target_with_source(
        &self,
        raw_target: &str,
        source: DiscoverySource,
    ) -> bool {
        let norm = match NormalizedHostname::new(raw_target) {
            Some(n) => n,
            None => return false,
        };

        if !self.scope.is_in_scope(&norm) {
            return false;
        }

        {
            let mut seen = self.seen_hostnames.lock().unwrap();
            if !seen.insert(norm.clone()) {
                return false;
            }
        }

        self.work_tx
            .send(WorkItem::ProbeTarget {
                hostname: norm,
                source,
            })
            .is_ok()
    }

    pub async fn submit_raw_target(&self, raw_target: &str) -> bool {
        self.submit_target_with_source(raw_target, DiscoverySource::Seed)
            .await
    }
}
