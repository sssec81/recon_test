//! Bounded source-map selection and local parsing. No discovery wordlists or
//! network operations live here.

use regex::Regex;
use reqwest::Url;
use serde::Deserialize;
use std::sync::LazyLock;

static SOURCE_MAPPING_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)([^\s*]+)"#)
        .unwrap()
});

#[derive(Debug, Deserialize)]
struct SourceMap {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSourceMap {
    pub source_files: Vec<String>,
    pub source_contents: Vec<String>,
}

/// Returns one explicitly referenced map, or one conventional `.js.map`
/// candidate when no explicit reference exists. Data URLs are intentionally not
/// fetched or decoded in this bounded phase.
pub fn map_candidate(script_url: &Url, script: &str) -> Option<Url> {
    let value = SOURCE_MAPPING_URL
        .captures(script)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str())
        .filter(|value| !value.starts_with("data:"));
    match value {
        Some(value) => script_url.join(value).ok(),
        None if script_url.path().ends_with(".js") => {
            let mut candidate = script_url.clone();
            candidate.set_path(&format!("{}.map", script_url.path()));
            candidate.set_query(None);
            Some(candidate)
        }
        None => None,
    }
}

pub fn parse(body: &str) -> Option<ParsedSourceMap> {
    let map: SourceMap = serde_json::from_str(body).ok()?;
    Some(ParsedSourceMap {
        source_files: map.sources,
        source_contents: map.sources_content.into_iter().flatten().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_one_explicit_or_conventional_map_and_parses_locally() {
        let script = Url::parse("https://example.com/assets/app.js?v=1").unwrap();
        assert_eq!(
            map_candidate(&script, "//# sourceMappingURL=app.min.js.map")
                .unwrap()
                .as_str(),
            "https://example.com/assets/app.min.js.map"
        );
        assert_eq!(
            map_candidate(&script, "const app = {};").unwrap().as_str(),
            "https://example.com/assets/app.js.map"
        );
        let map =
            parse(r#"{"sources":["src/api.ts"],"sourcesContent":["fetch('/api/users?id=1')"]}"#)
                .unwrap();
        assert_eq!(map.source_files, ["src/api.ts"]);
        assert_eq!(map.source_contents.len(), 1);
    }
}
