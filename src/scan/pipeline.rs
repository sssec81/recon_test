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
    state: Arc<Mutex<SchedulerState>>,
    work_tx: mpsc::UnboundedSender<WorkItem>,
    max_targets: usize,
}

#[derive(Default)]
struct SchedulerState {
    seen_hostnames: HashSet<NormalizedHostname>,
    limit_exceeded: bool,
}

impl Scheduler {
    pub fn new(
        scope: ScopePolicy,
        work_tx: mpsc::UnboundedSender<WorkItem>,
        max_targets: usize,
    ) -> Self {
        Self {
            scope,
            state: Arc::new(Mutex::new(SchedulerState::default())),
            work_tx,
            max_targets,
        }
    }

    pub fn limit_exceeded(&self) -> bool {
        self.state.lock().unwrap().limit_exceeded
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
            let mut state = self.state.lock().unwrap();
            if state.seen_hostnames.contains(&norm) {
                return false;
            }
            if state.seen_hostnames.len() >= self.max_targets {
                state.limit_exceeded = true;
                return false;
            }
            state.seen_hostnames.insert(norm.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn target_limit_rejects_new_hosts_but_allows_duplicates() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let scheduler = Scheduler::new(ScopePolicy::new(vec!["example.com".into()]), tx, 1);
        assert!(scheduler.submit_raw_target("example.com").await);
        assert!(!scheduler.submit_raw_target("example.com").await);
        assert!(!scheduler.limit_exceeded());
        assert!(!scheduler.submit_raw_target("api.example.com").await);
        assert!(scheduler.limit_exceeded());
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }
}
