use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn query_crtsh(client: &Client, domain: &str) -> Result<Vec<String>, String> {
    let query_val = format!("%.{domain}");
    let mut last_error = String::new();
    for attempt in 1..=3 {
        let result = client
            .get("https://crt.sh/")
            .query(&[("q", &query_val), ("output", &"json".to_string())])
            .timeout(Duration::from_secs(12))
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {
                match response.json::<Vec<CrtShEntry>>().await {
                    Ok(entries) => {
                        let mut names = HashSet::new();
                        for entry in entries {
                            for line in entry.name_value.lines() {
                                let name =
                                    line.trim().trim_start_matches("*.").to_ascii_lowercase();
                                if !name.is_empty() {
                                    names.insert(name);
                                }
                            }
                        }
                        let mut names: Vec<String> = names.into_iter().collect();
                        names.sort();
                        return Ok(names);
                    }
                    Err(error) => last_error = format!("invalid crt.sh JSON: {error}"),
                }
            }
            Ok(response) => last_error = format!("crt.sh HTTP {}", response.status()),
            Err(error) => last_error = format!("crt.sh request failed: {error}"),
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
        }
    }
    Err(format!(
        "crt.sh query for {domain} failed after 3 attempts: {last_error}"
    ))
}
