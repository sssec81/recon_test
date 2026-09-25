use crate::scan::scope::ScopePolicy;
use reqwest::{Client, Response, Url};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

#[derive(Clone, Default)]
pub struct ProbeAccounting {
    pub dns_operations: Arc<AtomicUsize>,
    pub tcp_operations: Arc<AtomicUsize>,
    pub tls_operations: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub struct ProbePolicy {
    scope: ScopePolicy,
    concurrency: Arc<Semaphore>,
    deadline: Option<Instant>,
    pub accounting: ProbeAccounting,
}

#[derive(Clone, Copy)]
pub enum ProbeKind {
    Dns,
    Tcp,
    Tls,
}

impl ProbePolicy {
    pub fn new(scope: ScopePolicy, concurrency: usize, deadline: Option<Instant>) -> Self {
        Self {
            scope,
            concurrency: Arc::new(Semaphore::new(concurrency.max(1))),
            deadline,
            accounting: ProbeAccounting::default(),
        }
    }
    pub async fn acquire(
        &self,
        host: &str,
        kind: ProbeKind,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, RequestError> {
        if !crate::scan::normalize::NormalizedHostname::new(host)
            .is_some_and(|name| self.scope.is_in_scope(&name))
        {
            return Err(RequestError::OutOfScope);
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(RequestError::Deadline);
        }
        let permit = if let Some(deadline) = self.deadline {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.concurrency.clone().acquire_owned(),
            )
            .await
            .map_err(|_| RequestError::Deadline)?
            .map_err(|_| RequestError::Closed)?
        } else {
            self.concurrency
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| RequestError::Closed)?
        };
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            drop(permit);
            return Err(RequestError::Deadline);
        }
        match kind {
            ProbeKind::Dns => self
                .accounting
                .dns_operations
                .fetch_add(1, Ordering::SeqCst),
            ProbeKind::Tcp => self
                .accounting
                .tcp_operations
                .fetch_add(1, Ordering::SeqCst),
            ProbeKind::Tls => self
                .accounting
                .tls_operations
                .fetch_add(1, Ordering::SeqCst),
        };
        Ok(permit)
    }
}

#[derive(Clone)]
pub struct RequestScheduler {
    client: Client,
    scope: ScopePolicy,
    global: Arc<Mutex<Instant>>,
    hosts: Arc<Mutex<HashMap<String, Instant>>>,
    concurrency: Arc<Semaphore>,
    remaining: Arc<AtomicUsize>,
    contacts: Arc<AtomicUsize>,
    global_interval: Duration,
    host_interval: Duration,
    deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    OutOfScope,
    BudgetExhausted,
    Deadline,
    Closed,
    RedirectLimit,
    RedirectLoop,
    MissingLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectTermination {
    FinalResponse,
    OutOfScope,
    RedirectLoop,
    RedirectLimit,
    MissingLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RedirectHop {
    pub requested_url: String,
    pub status: u16,
    pub location: Option<String>,
    pub destination_in_scope: Option<bool>,
}

pub struct ScheduledResponse {
    pub response: Option<Response>,
    pub initial_url: Url,
    pub last_status: Option<u16>,
    pub redirect_hops: usize,
    pub blocked_destination: Option<String>,
    pub termination: RedirectTermination,
    pub hops: Vec<RedirectHop>,
    pub requests_used: usize,
}
impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for RequestError {}

impl RequestScheduler {
    pub fn new(
        client: Client,
        scope: ScopePolicy,
        max_concurrency: usize,
        budget: usize,
        global_rps: u32,
        host_rps: u32,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            client,
            scope,
            global: Arc::new(Mutex::new(Instant::now() - Duration::from_secs(1))),
            hosts: Arc::new(Mutex::new(HashMap::new())),
            concurrency: Arc::new(Semaphore::new(max_concurrency.max(1))),
            remaining: Arc::new(AtomicUsize::new(budget)),
            contacts: Arc::new(AtomicUsize::new(0)),
            global_interval: interval(global_rps),
            host_interval: interval(host_rps),
            deadline,
        }
    }
    async fn pace(&self, url: &Url) -> Result<(), RequestError> {
        let wait = |last: Instant, interval: Duration| async move {
            let elapsed = last.elapsed();
            if elapsed < interval {
                tokio::time::sleep(interval - elapsed).await;
            }
        };
        let mut global = self.global.lock().await;
        wait(*global, self.global_interval).await;
        *global = Instant::now();
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let mut hosts = self.hosts.lock().await;
        let last = hosts
            .entry(host)
            .or_insert(Instant::now() - Duration::from_secs(1));
        wait(*last, self.host_interval).await;
        *last = Instant::now();
        Ok(())
    }
    pub async fn get(
        &self,
        url: &Url,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        let result = self.get_with_trace(url).await?;
        match (result.response, result.termination) {
            (Some(response), RedirectTermination::FinalResponse) => Ok(response),
            (_, RedirectTermination::OutOfScope) => Err(RequestError::OutOfScope.into()),
            (_, RedirectTermination::RedirectLoop) => Err(RequestError::RedirectLoop.into()),
            (_, RedirectTermination::RedirectLimit) => Err(RequestError::RedirectLimit.into()),
            (_, RedirectTermination::MissingLocation) => Err(RequestError::MissingLocation.into()),
            _ => Err(RequestError::Closed.into()),
        }
    }

    pub async fn get_with_trace(
        &self,
        url: &Url,
    ) -> Result<ScheduledResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.get_with_trace_limited(url, 6).await
    }

    pub async fn get_with_trace_limited(
        &self,
        url: &Url,
        max_contacts: usize,
    ) -> Result<ScheduledResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut current_url = url.clone();
        let mut visited = HashSet::new();
        let mut hops = 0;
        let mut trace = Vec::new();
        if max_contacts == 0 {
            return Err(RequestError::BudgetExhausted.into());
        }
        for _ in 0..=5 {
            if !visited.insert(current_url.to_string()) {
                return Ok(ScheduledResponse {
                    response: None,
                    initial_url: url.clone(),
                    last_status: None,
                    redirect_hops: hops,
                    blocked_destination: None,
                    termination: RedirectTermination::RedirectLoop,
                    requests_used: trace.len(),
                    hops: trace,
                });
            }
            let response = self.get_one(&current_url).await?;
            let status = response.status().as_u16();
            if !response.status().is_redirection() {
                trace.push(RedirectHop {
                    requested_url: safe_url(&current_url),
                    status,
                    location: None,
                    destination_in_scope: None,
                });
                return Ok(ScheduledResponse {
                    response: Some(response),
                    initial_url: url.clone(),
                    last_status: Some(status),
                    redirect_hops: hops,
                    blocked_destination: None,
                    termination: RedirectTermination::FinalResponse,
                    requests_used: trace.len(),
                    hops: trace,
                });
            }
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| current_url.join(value).ok())
                .ok_or(RequestError::MissingLocation);
            let Ok(next) = next else {
                trace.push(RedirectHop {
                    requested_url: safe_url(&current_url),
                    status,
                    location: None,
                    destination_in_scope: None,
                });
                return Ok(ScheduledResponse {
                    response: Some(response),
                    initial_url: url.clone(),
                    last_status: Some(status),
                    redirect_hops: hops,
                    blocked_destination: None,
                    termination: RedirectTermination::MissingLocation,
                    requests_used: trace.len(),
                    hops: trace,
                });
            };
            let in_scope = self.scope.allows_redirect_url(&next);
            trace.push(RedirectHop {
                requested_url: safe_url(&current_url),
                status,
                location: Some(safe_url(&next)),
                destination_in_scope: Some(in_scope),
            });
            drop(response);
            if !in_scope {
                let blocked_destination =
                    crate::scan::normalize::normalize_endpoint(next.as_str(), None)
                        .map(|endpoint| endpoint.canonical_url);
                return Ok(ScheduledResponse {
                    response: None,
                    initial_url: url.clone(),
                    last_status: Some(status),
                    redirect_hops: hops + 1,
                    blocked_destination,
                    termination: RedirectTermination::OutOfScope,
                    requests_used: trace.len(),
                    hops: trace,
                });
            }
            if trace.len() >= max_contacts {
                return Ok(ScheduledResponse {
                    response: None,
                    initial_url: url.clone(),
                    last_status: Some(status),
                    redirect_hops: hops + 1,
                    blocked_destination: None,
                    termination: RedirectTermination::RedirectLimit,
                    requests_used: trace.len(),
                    hops: trace,
                });
            }
            current_url = next;
            hops += 1;
        }
        Ok(ScheduledResponse {
            response: None,
            initial_url: url.clone(),
            last_status: None,
            redirect_hops: hops,
            blocked_destination: None,
            termination: RedirectTermination::RedirectLimit,
            requests_used: trace.len(),
            hops: trace,
        })
    }

    async fn get_one(
        &self,
        url: &Url,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        if !self.scope.allows_redirect_url(url) {
            return Err(RequestError::OutOfScope.into());
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(RequestError::Deadline.into());
        }
        let _permit = if let Some(deadline) = self.deadline {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.concurrency.acquire(),
            )
            .await
            .map_err(|_| RequestError::Deadline)?
            .map_err(|_| RequestError::Closed)?
        } else {
            self.concurrency
                .acquire()
                .await
                .map_err(|_| RequestError::Closed)?
        };
        self.pace(url).await?;
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(RequestError::Deadline.into());
        }
        let mut current = self.remaining.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return Err(RequestError::BudgetExhausted.into());
            }
            match self.remaining.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        self.contacts.fetch_add(1, Ordering::SeqCst);
        Ok(self.client.get(url.clone()).send().await?)
    }

    pub fn contacts(&self) -> usize {
        self.contacts.load(Ordering::SeqCst)
    }
}
fn safe_url(url: &Url) -> String {
    crate::scan::normalize::normalize_endpoint(url.as_str(), None)
        .map(|endpoint| endpoint.canonical_url)
        .unwrap_or_else(|| "<invalid-endpoint>".into())
}
fn interval(rps: u32) -> Duration {
    if rps == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(1.0 / rps as f64)
    }
}

#[derive(Clone)]
pub struct ScanContext {
    pub scope: ScopePolicy,
    pub target_http: Arc<RequestScheduler>,
    pub probes: Arc<ProbePolicy>,
    pub deadline: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn policy(deadline: Option<Instant>) -> ProbePolicy {
        ProbePolicy::new(ScopePolicy::new(vec!["example.com".into()]), 1, deadline)
    }

    #[tokio::test]
    async fn probe_policy_rejects_scope_and_deadline_before_accounting() {
        let p = policy(None);
        assert!(matches!(
            p.acquire("evil.example", ProbeKind::Dns).await,
            Err(RequestError::OutOfScope)
        ));
        assert_eq!(p.accounting.dns_operations.load(Ordering::SeqCst), 0);
        let expired = policy(Some(Instant::now() - Duration::from_secs(1)));
        assert!(matches!(
            expired.acquire("example.com", ProbeKind::Tcp).await,
            Err(RequestError::Deadline)
        ));
        assert_eq!(expired.accounting.tcp_operations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn probe_policy_accounts_by_protocol() {
        let p = policy(None);
        drop(p.acquire("example.com", ProbeKind::Dns).await.unwrap());
        drop(p.acquire("example.com", ProbeKind::Tls).await.unwrap());
        assert_eq!(p.accounting.dns_operations.load(Ordering::SeqCst), 1);
        assert_eq!(p.accounting.tcp_operations.load(Ordering::SeqCst), 0);
        assert_eq!(p.accounting.tls_operations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn probe_policy_does_not_count_work_that_expires_waiting_for_a_permit() {
        let p = ProbePolicy::new(
            ScopePolicy::new(vec!["example.com".into()]),
            1,
            Some(Instant::now() + Duration::from_millis(30)),
        );
        let held = p.acquire("example.com", ProbeKind::Dns).await.unwrap();
        let waiting = {
            let p = p.clone();
            tokio::spawn(async move { p.acquire("example.com", ProbeKind::Tcp).await })
        };
        assert!(matches!(
            waiting.await.unwrap(),
            Err(RequestError::Deadline)
        ));
        drop(held);
        assert_eq!(p.accounting.tcp_operations.load(Ordering::SeqCst), 0);
    }

    fn scheduler(
        budget: usize,
        deadline: Option<Instant>,
        global_rps: u32,
        host_rps: u32,
    ) -> RequestScheduler {
        RequestScheduler::new(
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ScopePolicy::new(vec!["example.com".into()]),
            1,
            budget,
            global_rps,
            host_rps,
            deadline,
        )
    }

    #[tokio::test]
    async fn scheduler_rejects_scope_budget_and_deadline_before_io() {
        let url: Url = "http://example.com/".parse().unwrap();
        assert!(matches!(
            scheduler(1, None, 0, 0)
                .get(&"http://evil.test/".parse().unwrap())
                .await
                .unwrap_err()
                .downcast_ref::<RequestError>(),
            Some(RequestError::OutOfScope)
        ));
        let exhausted = scheduler(0, None, 0, 0);
        assert!(matches!(
            exhausted
                .get(&url)
                .await
                .unwrap_err()
                .downcast_ref::<RequestError>(),
            Some(RequestError::BudgetExhausted)
        ));
        let expired = scheduler(1, Some(Instant::now() - Duration::from_secs(1)), 0, 0);
        assert!(matches!(
            expired
                .get(&url)
                .await
                .unwrap_err()
                .downcast_ref::<RequestError>(),
            Some(RequestError::Deadline)
        ));
    }

    #[tokio::test]
    async fn scheduler_paces_global_and_host_state() {
        let s = scheduler(2, None, 20, 20);
        let url: Url = "http://example.com/".parse().unwrap();
        s.pace(&url).await.unwrap();
        let started = Instant::now();
        s.pace(&url).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn redirect_trace_preserves_blocked_evidence_without_contact_or_double_follow() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let contacted = Arc::new(AtomicUsize::new(0));
        let count = contacted.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 512];
                let size = socket.read(&mut request).await.unwrap();
                let path = String::from_utf8_lossy(&request[..size]);
                let response = if path.contains("GET /start ") {
                    "HTTP/1.1 302 Found\r\nLocation: /middle\r\nContent-Length: 0\r\n\r\n"
                } else {
                    "HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/final?token=secret\r\nContent-Length: 0\r\n\r\n"
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let scheduler = RequestScheduler::new(
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ScopePolicy::new(vec!["127.0.0.1".into()]),
            1,
            3,
            0,
            0,
            None,
        );
        let start: Url = format!("http://{address}/start").parse().unwrap();
        let traced = scheduler.get_with_trace(&start).await.unwrap();
        assert_eq!(traced.initial_url, start);
        assert_eq!(traced.last_status, Some(302));
        assert_eq!(traced.redirect_hops, 2);
        assert_eq!(traced.termination, RedirectTermination::OutOfScope);
        assert_eq!(
            traced.blocked_destination.as_deref(),
            Some("https://outside.invalid/final")
        );
        assert_eq!(contacted.load(Ordering::SeqCst), 2);
        assert_eq!(scheduler.remaining.load(Ordering::SeqCst), 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn scheduler_does_not_spend_budget_when_deadline_expires_waiting() {
        let s = scheduler(1, Some(Instant::now() + Duration::from_millis(30)), 0, 0);
        let held = s.concurrency.clone().acquire_owned().await.unwrap();
        let url: Url = "http://example.com/".parse().unwrap();
        let waiting = {
            let s = s.clone();
            tokio::spawn(async move { s.get(&url).await })
        };
        let error = waiting.await.unwrap().unwrap_err();
        assert!(matches!(
            error.downcast_ref::<RequestError>(),
            Some(RequestError::Deadline)
        ));
        drop(held);
        assert_eq!(s.remaining.load(Ordering::SeqCst), 1);
    }

    async fn redirect_server(
        routes: Arc<std::collections::HashMap<&'static str, &'static str>>,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let routes = routes.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut request = [0; 1024];
                    let n = socket.read(&mut request).await.unwrap_or(0);
                    let path = std::str::from_utf8(&request[..n])
                        .ok()
                        .and_then(|v| v.split_whitespace().nth(1))
                        .unwrap_or("/");
                    seen.fetch_add(1, Ordering::SeqCst);
                    let response = routes
                        .get(path)
                        .copied()
                        .unwrap_or("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), count, task)
    }

    #[tokio::test]
    async fn redirects_are_hop_accounted_and_safe_at_concurrency_one() {
        let routes = Arc::new(std::collections::HashMap::from([
            (
                "/start",
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
            ),
            ("/final", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        ]));
        let (base, count, task) = redirect_server(routes).await;
        let host = base.trim_start_matches("http://").to_string();
        let s = RequestScheduler::new(
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ScopePolicy::new(vec![host]),
            1,
            2,
            0,
            0,
            None,
        );
        assert_eq!(
            s.get(&format!("{base}/start").parse().unwrap())
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn redirect_matrix_rejects_escape_and_terminates_loops_and_limits() {
        let routes = Arc::new(std::collections::HashMap::from([
            (
                "/absolute",
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
            ),
            (
                "/multi1",
                "HTTP/1.1 302 Found\r\nLocation: /multi2\r\nContent-Length: 0\r\n\r\n",
            ),
            (
                "/multi2",
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
            ),
            (
                "/escape",
                "HTTP/1.1 302 Found\r\nLocation: http://evil.invalid/\r\nContent-Length: 0\r\n\r\n",
            ),
            (
                "/a",
                "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
            ),
            (
                "/b",
                "HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n",
            ),
            ("/final", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        ]));
        let (base, count, task) = redirect_server(routes).await;
        let host = base.trim_start_matches("http://").to_string();
        let s = RequestScheduler::new(
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ScopePolicy::new(vec![host]),
            2,
            20,
            0,
            0,
            None,
        );
        assert!(
            s.get(&format!("{base}/absolute").parse().unwrap())
                .await
                .is_ok()
        );
        assert!(
            s.get(&format!("{base}/multi1").parse().unwrap())
                .await
                .is_ok()
        );
        assert!(matches!(
            s.get(&format!("{base}/escape").parse().unwrap())
                .await
                .unwrap_err()
                .downcast_ref::<RequestError>(),
            Some(RequestError::OutOfScope)
        ));
        assert!(matches!(
            s.get(&format!("{base}/a").parse().unwrap())
                .await
                .unwrap_err()
                .downcast_ref::<RequestError>(),
            Some(RequestError::RedirectLoop)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 8); // 2 + 3 + 1 + 2; escaped host is never contacted.
        task.abort();
    }

    #[tokio::test]
    async fn five_redirects_mean_initial_request_plus_five_followed_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut b = [0; 256];
                    let n = socket.read(&mut b).await.unwrap();
                    let path = std::str::from_utf8(&b[..n])
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    let next = path.trim_start_matches('/').parse::<usize>().unwrap_or(0) + 1;
                    seen.fetch_add(1, Ordering::SeqCst);
                    let r = format!(
                        "HTTP/1.1 302 Found\r\nLocation: /{next}\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = socket.write_all(r.as_bytes()).await;
                });
            }
        });
        let s = RequestScheduler::new(
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ScopePolicy::new(vec![base.trim_start_matches("http://").into()]),
            1,
            10,
            0,
            0,
            None,
        );
        assert!(matches!(
            s.get(&format!("{base}/0").parse().unwrap())
                .await
                .unwrap_err()
                .downcast_ref::<RequestError>(),
            Some(RequestError::RedirectLimit)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 6);
        server.abort();
    }

    #[tokio::test]
    async fn scheduler_enforces_configured_concurrency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let a = active.clone();
        let m = max.clone();
        let server = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let a = a.clone();
                let m = m.clone();
                handlers.spawn(async move {
                    let now = a.fetch_add(1, Ordering::SeqCst) + 1;
                    m.fetch_max(now, Ordering::SeqCst);
                    let mut b = [0; 128];
                    let _ = socket.read(&mut b).await;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    a.fetch_sub(1, Ordering::SeqCst);
                });
            }
            while handlers.join_next().await.is_some() {}
        });
        let s = Arc::new(RequestScheduler::new(
            Client::builder().build().unwrap(),
            ScopePolicy::new(vec![base.trim_start_matches("http://").into()]),
            2,
            4,
            0,
            0,
            None,
        ));
        let mut jobs = Vec::new();
        for _ in 0..4 {
            let s = s.clone();
            let u: Url = base.parse().unwrap();
            jobs.push(tokio::spawn(async move {
                s.get(&u).await.unwrap();
            }));
        }
        for job in jobs {
            job.await.unwrap();
        }
        assert_eq!(max.load(Ordering::SeqCst), 2);
        server.await.unwrap();
    }
}
