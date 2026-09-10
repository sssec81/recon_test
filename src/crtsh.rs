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

    let query_val = format!("%.{}", clean_domain);
    let mut discovered = HashSet::new();
    let max_attempts = 3;

    for attempt in 1..=max_attempts {
        let req_res = client
            .get("https://crt.sh/")
            .query(&[("q", &query_val), ("output", &"json".to_string())])
            .header("User-Agent", "recon_test/1.0.0")
            .timeout(Duration::from_secs(12))
            .send()
            .await;

        match req_res {
            Ok(response) if response.status().is_success() => {
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
                    return discovered.into_iter().collect();
                }
            }
            Ok(res) => {
                if attempt == max_attempts {
                    eprintln!(
                        "⚠️  [crt.sh] HTTP error {} querying subdomains for '{}' after {} attempts",
                        res.status(),
                        clean_domain,
                        max_attempts
                    );
                }
            }
            Err(e) => {
                if attempt == max_attempts {
                    eprintln!(
                        "⚠️  [crt.sh] Request failed for domain '{}': {} (after {} attempts)",
                        clean_domain, e, max_attempts
                    );
                }
            }
        }

        if attempt < max_attempts {
            tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
        }
    }

    discovered.into_iter().collect()
}
