use crate::scan::scope::ScopePolicy;
use crate::triage::crawl::{extract_js_calls, extract_links, is_html, is_safe_url, script_text};
use crate::triage::model::{EndpointRecord, HttpEvidence, Page, ResponseAnomaly};
use reqwest::Url;
use scraper::{Html, Selector};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Default)]
pub struct Inventory {
    endpoints: BTreeMap<String, EndpointRecord>,
    responses: BTreeMap<String, Vec<ObservedResponse>>,
}

#[derive(Clone)]
struct ObservedResponse {
    url: String,
    status: u16,
    content_type: Option<String>,
    evidence: HttpEvidence,
}

fn route_template(url: &Url) -> String {
    let mut template = url.clone();
    template.set_query(None);
    template.set_fragment(None);
    let path = url
        .path()
        .split('/')
        .map(|segment| {
            if !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()) {
                "{id}"
            } else if Uuid::parse_str(segment).is_ok() {
                "{uuid}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    template.set_path(&path);
    template.to_string()
}

fn parameter_names(url: &Url) -> BTreeSet<String> {
    url.query_pairs().map(|(key, _)| key.into_owned()).collect()
}

impl Inventory {
    pub fn record(
        &mut self,
        url: &Url,
        method: &str,
        source: &str,
        extra_parameters: impl IntoIterator<Item = String>,
    ) {
        let template = route_template(url);
        let key = format!("{method} {template}");
        let endpoint = self.endpoints.entry(key).or_insert_with(|| EndpointRecord {
            method: method.into(),
            url_template: template,
            parameters: BTreeSet::new(),
            sources: BTreeSet::new(),
            status_codes: BTreeSet::new(),
            content_types: BTreeSet::new(),
        });
        endpoint.parameters.extend(parameter_names(url));
        endpoint.parameters.extend(extra_parameters);
        endpoint.sources.insert(source.into());
    }

    pub fn record_page(&mut self, url: &Url, page: &Page, scope: &ScopePolicy) {
        self.record(url, "GET", "triage_fetch", std::iter::empty());
        let key = format!("GET {}", route_template(url));
        if let Some(endpoint) = self.endpoints.get_mut(&key) {
            if let Some(status) = page.evidence.status {
                endpoint.status_codes.insert(status);
            }
            if let Some(content_type) = &page.evidence.content_type {
                endpoint.content_types.insert(
                    content_type
                        .split(';')
                        .next()
                        .unwrap_or(content_type)
                        .trim()
                        .to_ascii_lowercase(),
                );
            }
        }
        if let Some(status) = page.evidence.status
            && !url.query().is_none_or(str::is_empty)
        {
            let mut exact_route = url.clone();
            exact_route.set_query(None);
            exact_route.set_fragment(None);
            let signature = format!(
                "{}?{}",
                exact_route,
                parameter_names(url)
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("&")
            );
            self.responses
                .entry(signature)
                .or_default()
                .push(ObservedResponse {
                    url: url.to_string(),
                    status,
                    content_type: page.evidence.content_type.clone(),
                    evidence: page.evidence.clone(),
                });
        }
        for link in extract_links(page, url, scope) {
            self.record(&link, "GET", "page_or_script", std::iter::empty());
        }
        if let Some(script) = script_text(page) {
            for (endpoint, method) in extract_js_calls(&script, url, scope) {
                self.record(&endpoint, &method, "javascript_call", std::iter::empty());
            }
        }
        if is_html(&page.evidence.content_type) {
            let document = Html::parse_document(&page.body);
            if let (Ok(form_selector), Ok(field_selector)) = (
                Selector::parse("form"),
                Selector::parse("input[name], select[name], textarea[name]"),
            ) {
                for form in document.select(&form_selector) {
                    let method = form
                        .value()
                        .attr("method")
                        .unwrap_or("GET")
                        .to_ascii_uppercase();
                    if !matches!(method.as_str(), "GET" | "POST") {
                        continue;
                    }
                    let action = form.value().attr("action").unwrap_or(url.as_str());
                    if let Ok(action_url) = url.join(action)
                        && is_safe_url(&action_url, scope)
                    {
                        let fields = form
                            .select(&field_selector)
                            .filter_map(|field| field.value().attr("name"))
                            .map(str::to_string);
                        self.record(&action_url, &method, "html_form", fields);
                    }
                }
            }
        }
    }

    pub fn anomalies(&self) -> Vec<ResponseAnomaly> {
        let mut anomalies = Vec::new();
        for responses in self.responses.values() {
            let failure = responses.iter().find(|item| item.status >= 500);
            let success = responses
                .iter()
                .find(|item| (200..300).contains(&item.status));
            if let (Some(failure), Some(success)) = (failure, success)
                && failure.url != success.url
                && let Ok(url) = Url::parse(&failure.url)
            {
                let names = parameter_names(&url).into_iter().collect::<Vec<_>>();
                anomalies.push(ResponseAnomaly {
                    url_template: route_template(&url),
                    parameter: names.join(", "),
                    baseline_url: failure.url.clone(),
                    control_url: success.url.clone(),
                    baseline_status: failure.status,
                    control_status: success.status,
                    baseline_content_type: failure.content_type.clone(),
                    control_content_type: success.content_type.clone(),
                    baseline_evidence: failure.evidence.clone(),
                    control_evidence: success.evidence.clone(),
                });
            }
        }
        anomalies
    }

    pub fn endpoints(&self) -> Vec<EndpointRecord> {
        self.endpoints.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::model::HttpEvidence;

    fn page(url: &str, status: u16, body: &str) -> Page {
        Page {
            evidence: HttpEvidence {
                requested_url: url.into(),
                final_url: Some(url.into()),
                status: Some(status),
                content_type: Some("text/html".into()),
                bytes: body.len(),
                body_sha256: None,
                title: None,
                body_excerpt: None,
                elapsed_ms: 0,
                error: None,
                fingerprint: None,
            },
            body: body.into(),
        }
    }

    #[test]
    fn records_form_fields_without_submitting_form() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let url = Url::parse("https://example.com/").unwrap();
        let mut inventory = Inventory::default();
        inventory.record_page(&url, &page(url.as_str(), 200,
            r#"<form method="post" action="/api/search"><input name="query"><input name="page"></form>"#), &scope);
        let endpoint = inventory
            .endpoints()
            .into_iter()
            .find(|item| item.method == "POST")
            .unwrap();
        assert_eq!(endpoint.url_template, "https://example.com/api/search");
        assert!(endpoint.parameters.contains("query"));
        assert!(endpoint.parameters.contains("page"));
    }

    #[test]
    fn compares_only_same_route_and_parameter_shape() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let mut inventory = Inventory::default();
        for (url, status) in [
            ("https://example.com/api/items?id=1", 200),
            ("https://example.com/api/items?id=2", 500),
            ("https://example.com/api/items?page=2", 200),
        ] {
            inventory.record_page(&Url::parse(url).unwrap(), &page(url, status, ""), &scope);
        }
        let anomalies = inventory.anomalies();
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].parameter, "id");
    }
}
