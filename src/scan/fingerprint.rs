use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingBucket {
    VeryFast,
    Fast,
    Medium,
    Slow,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResponseFingerprint {
    pub status: u16,
    pub body_length: usize,
    pub captured_length: usize,
    pub body_complete: bool,
    pub raw_hash: String,
    pub normalized_hash: String,
    pub content_type: Option<String>,
    pub header_hash: String,
    pub redirect_target: Option<String>,
    pub json_shape_hash: Option<String>,
    pub timing_bucket: TimingBucket,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn textual(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|v| {
        let v = v.to_ascii_lowercase();
        v.starts_with("text/")
            || v.contains("json")
            || v.contains("javascript")
            || v.contains("xml")
    })
}
fn normalize_text(value: String) -> String {
    let uuid =
        regex::Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .unwrap();
    let timestamp =
        regex::Regex::new(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b").unwrap();
    timestamp
        .replace_all(&uuid.replace_all(&value, "<UUID>"), "<TIMESTAMP>")
        .into_owned()
}
fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), canonical_json(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json).collect())
        }
        serde_json::Value::String(v) => serde_json::Value::String(normalize_text(v.clone())),
        v => v.clone(),
    }
}
fn shape(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), shape(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(shape).collect())
        }
        serde_json::Value::String(_) => serde_json::Value::String("string".into()),
        serde_json::Value::Number(_) => serde_json::Value::String("number".into()),
        serde_json::Value::Bool(_) => serde_json::Value::String("bool".into()),
        serde_json::Value::Null => serde_json::Value::String("null".into()),
    }
}
pub fn fingerprint(
    status: u16,
    body: &[u8],
    body_length: usize,
    body_complete: bool,
    content_type: Option<&str>,
    headers: &reqwest::header::HeaderMap,
    elapsed: Option<u64>,
) -> ResponseFingerprint {
    let raw_hash = hash(body);
    let parsed = if textual(content_type) {
        serde_json::from_slice::<serde_json::Value>(body).ok()
    } else {
        None
    };
    let normalized = match &parsed {
        Some(v) => serde_json::to_vec(&canonical_json(v)).unwrap_or_else(|_| body.to_vec()),
        None if textual(content_type) => {
            normalize_text(String::from_utf8_lossy(body).into_owned()).into_bytes()
        }
        None => body.to_vec(),
    };
    let json_shape_hash = parsed
        .as_ref()
        .map(|v| hash(&serde_json::to_vec(&shape(v)).unwrap()));
    let mut selected = Vec::new();
    for name in [
        "content-type",
        "content-encoding",
        "cache-control",
        "location",
        "www-authenticate",
        "allow",
    ] {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            selected.push(format!("{name}:{v}"));
        }
    }
    selected.sort();
    let redirect_target = headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let timing_bucket = match elapsed {
        None => TimingBucket::Unknown,
        Some(v) if v < 100 => TimingBucket::VeryFast,
        Some(v) if v < 500 => TimingBucket::Fast,
        Some(v) if v < 1500 => TimingBucket::Medium,
        Some(_) => TimingBucket::Slow,
    };
    ResponseFingerprint {
        status,
        body_length,
        captured_length: body.len(),
        body_complete,
        raw_hash,
        normalized_hash: hash(&normalized),
        content_type: content_type.map(str::to_string),
        header_hash: hash(selected.join("\n").as_bytes()),
        redirect_target,
        json_shape_hash,
        timing_bucket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn volatile_and_json_shapes_are_deterministic() {
        let h = reqwest::header::HeaderMap::new();
        let a = fingerprint(
            200,
            br#"{"id":1,"at":"2026-01-01T00:00:00Z"}"#,
            38,
            true,
            Some("application/json"),
            &h,
            Some(3),
        );
        let b = fingerprint(
            200,
            br#"{"at":"2027-01-01T00:00:00Z","id":2}"#,
            38,
            true,
            Some("application/json"),
            &h,
            Some(3),
        );
        assert_ne!(a.raw_hash, b.raw_hash);
        assert_ne!(a.normalized_hash, b.normalized_hash);
        assert_eq!(a.json_shape_hash, b.json_shape_hash);
    }

    #[test]
    fn fixture_matrix_covers_text_json_binary_headers_redirects_and_capture_metadata() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("cache-control", "no-store".parse().unwrap());
        headers.insert("set-cookie", "secret=value".parse().unwrap());
        headers.insert("location", "/next".parse().unwrap());
        let exact = fingerprint(
            200,
            b"hello",
            5,
            true,
            Some("text/plain"),
            &headers,
            Some(99),
        );
        assert_eq!(
            exact.raw_hash,
            fingerprint(
                200,
                b"hello",
                5,
                true,
                Some("text/plain"),
                &headers,
                Some(99)
            )
            .raw_hash
        );
        assert_ne!(
            exact.normalized_hash,
            fingerprint(
                200,
                b"goodbye",
                7,
                true,
                Some("text/plain"),
                &headers,
                Some(99)
            )
            .normalized_hash
        );
        let reordered = fingerprint(
            200,
            br#"{"b":2,"a":1}"#,
            13,
            true,
            Some("application/json"),
            &headers,
            None,
        );
        let ordered = fingerprint(
            200,
            br#"{"a":1,"b":2}"#,
            13,
            true,
            Some("application/json"),
            &headers,
            None,
        );
        assert_eq!(reordered.normalized_hash, ordered.normalized_hash);
        assert_ne!(
            reordered.json_shape_hash,
            fingerprint(
                200,
                br#"{"a":1,"b":2,"c":3}"#,
                19,
                true,
                Some("application/json"),
                &headers,
                None
            )
            .json_shape_hash
        );
        assert_ne!(
            fingerprint(
                200,
                br#"[1,2]"#,
                5,
                true,
                Some("application/json"),
                &headers,
                None
            )
            .normalized_hash,
            fingerprint(
                200,
                br#"[2,1]"#,
                5,
                true,
                Some("application/json"),
                &headers,
                None
            )
            .normalized_hash
        );
        let binary = fingerprint(
            200,
            &[0xff, 0, 1],
            3,
            true,
            Some("application/octet-stream"),
            &headers,
            None,
        );
        assert_eq!(binary.raw_hash, binary.normalized_hash);
        let partial = fingerprint(200, b"same", 999, false, Some("text/plain"), &headers, None);
        assert_eq!(partial.captured_length, 4);
        assert!(!partial.body_complete);
        assert_eq!(partial.redirect_target, Some("/next".into()));
        assert_eq!(partial.timing_bucket, TimingBucket::Unknown);
        assert!(!format!("{:?}", partial.header_hash).contains("secret"));
    }
}
