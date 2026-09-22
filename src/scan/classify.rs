//! Deterministic inventory classification. These tags are descriptive only;
//! they are neither findings nor confidence assessments.

use std::collections::BTreeSet;

pub const ENDPOINT_CLASSES: &[&str] = &[
    "Authentication",
    "UserProfile",
    "Account",
    "Admin",
    "Internal",
    "Debug",
    "Upload",
    "Download",
    "Export",
    "Import",
    "Payment",
    "Order",
    "Document",
    "Search",
    "Redirect",
    "Webhook",
    "GraphQL",
    "Api",
    "Static",
    "Unknown",
];
pub const PARAMETER_SEMANTICS: &[&str] = &[
    "Url",
    "Redirect",
    "File",
    "Path",
    "ObjectId",
    "UserId",
    "AccountId",
    "Search",
    "Callback",
    "Webhook",
    "Template",
    "Query",
    "Pagination",
    "Unknown",
];

pub fn endpoint_classes(canonical_url: &str, raw_urls: &[String]) -> BTreeSet<&'static str> {
    let value = format!("{} {}", canonical_url, raw_urls.join(" ")).to_ascii_lowercase();
    let mut tags = BTreeSet::new();
    tag(
        &mut tags,
        &value,
        "Authentication",
        &[
            "login", "logout", "signin", "signup", "auth", "oauth", "sso",
        ],
    );
    tag(
        &mut tags,
        &value,
        "UserProfile",
        &["user", "profile", "member"],
    );
    tag(
        &mut tags,
        &value,
        "Account",
        &["account", "tenant", "organization", "org/"],
    );
    tag(&mut tags, &value, "Admin", &["admin", "administrator"]);
    tag(
        &mut tags,
        &value,
        "Internal",
        &["internal", "private", "staff"],
    );
    tag(
        &mut tags,
        &value,
        "Debug",
        &["debug", "trace", "metrics", "actuator"],
    );
    tag(&mut tags, &value, "Upload", &["upload", "attach"]);
    tag(&mut tags, &value, "Download", &["download", "fetch-file"]);
    tag(&mut tags, &value, "Export", &["export", "report"]);
    tag(&mut tags, &value, "Import", &["import"]);
    tag(
        &mut tags,
        &value,
        "Payment",
        &["payment", "billing", "invoice", "checkout"],
    );
    tag(&mut tags, &value, "Order", &["order", "cart"]);
    tag(
        &mut tags,
        &value,
        "Document",
        &["document", "document", "file", "pdf"],
    );
    tag(&mut tags, &value, "Search", &["search", "query", "find"]);
    tag(
        &mut tags,
        &value,
        "Redirect",
        &["redirect", "returnurl", "return_url", "next", "continue"],
    );
    tag(&mut tags, &value, "Webhook", &["webhook", "hook"]);
    tag(&mut tags, &value, "GraphQL", &["graphql", "/gql"]);
    tag(&mut tags, &value, "Api", &["/api", "/v1", "/v2", "/v3"]);
    tag(
        &mut tags,
        &value,
        "Static",
        &["/assets/", "/static/", ".css", ".js", ".png", ".svg"],
    );
    if tags.is_empty() {
        tags.insert("Unknown");
    }
    tags
}

pub fn parameter_semantic(name: &str) -> &'static str {
    let value = name.to_ascii_lowercase().replace(['_', '-'], "");
    let semantic = if [
        "redirect",
        "redirecturi",
        "returnurl",
        "returnto",
        "next",
        "continue",
        "destination",
    ]
    .contains(&value.as_str())
    {
        "Redirect"
    } else if ["url", "uri", "link", "endpoint", "target"].contains(&value.as_str()) {
        "Url"
    } else if ["file", "filename", "attachment", "upload"].contains(&value.as_str()) {
        "File"
    } else if ["path", "directory", "folder"].contains(&value.as_str()) {
        "Path"
    } else if ["userid", "uid", "user"].contains(&value.as_str()) {
        "UserId"
    } else if ["accountid", "account", "tenantid", "orgid"].contains(&value.as_str()) {
        "AccountId"
    } else if ["id", "objectid", "documentid", "orderid", "resourceid"].contains(&value.as_str()) {
        "ObjectId"
    } else if ["search", "q", "query", "term", "keyword"].contains(&value.as_str()) {
        "Search"
    } else if ["callback", "callbackurl", "cb"].contains(&value.as_str()) {
        "Callback"
    } else if ["webhook", "hook", "webhookurl"].contains(&value.as_str()) {
        "Webhook"
    } else if ["template", "view", "layout"].contains(&value.as_str()) {
        "Template"
    } else if ["page", "perpage", "limit", "offset", "cursor"].contains(&value.as_str()) {
        "Pagination"
    } else if ["filter", "sort", "fields", "include"].contains(&value.as_str()) {
        "Query"
    } else {
        "Unknown"
    };
    debug_assert!(PARAMETER_SEMANTICS.contains(&semantic));
    semantic
}

fn tag(tags: &mut BTreeSet<&'static str>, value: &str, tag: &'static str, terms: &[&str]) {
    debug_assert!(ENDPOINT_CLASSES.contains(&tag));
    if terms.iter().any(|term| value.contains(term)) {
        tags.insert(tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_multiple_tags_and_parameter_meaning() {
        let tags = endpoint_classes(
            "https://example.com/api/users/123",
            &["https://example.com/api/users/123?redirect=/home".into()],
        );
        assert!(tags.contains("Api"));
        assert!(tags.contains("UserProfile"));
        assert!(tags.contains("Redirect"));
        assert_eq!(parameter_semantic("redirect"), "Redirect");
        assert_eq!(parameter_semantic("account_id"), "AccountId");
        assert_eq!(parameter_semantic("unrelated"), "Unknown");
    }
}
