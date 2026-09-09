use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn query_crtsh(client: &Client, domain: &str) -> Vec<String> {
    let clean_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.")
        .trim_end_matches('/')
        .to_lowercase();

    if clean_domain.is_empty() {
        return Vec::new();
    }

    let url = format!("https://crt.sh/?q=%.{}&output=json", clean_domain);

    let mut discovered = HashSet::new();

    let req_fut = client
        .get(&url)
        .header("User-Agent", "recon_test/0.7.0")
        .timeout(Duration::from_secs(12))
        .send();

    if let Ok(response) = req_fut.await {
        if response.status().is_success() {
            if let Ok(entries) = response.json::<Vec<CrtShEntry>>().await {
                for entry in entries {
                    for line in entry.name_value.lines() {
                        let mut name = line.trim().to_lowercase();
                        if name.starts_with("*.") {
                            name = name["*.".len()..].to_string();
                        }
                        if !name.is_empty() && name.contains(&clean_domain) {
                            discovered.insert(name);
                        }
                    }
                }
            }
        }
    }

    discovered.into_iter().collect()
}
