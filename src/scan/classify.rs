//! Deterministic inventory classification. These labels describe inventory;
//! they are not findings, vulnerability hypotheses, or confidence changes.

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

/// Classify only stable endpoint identity (host and normalized path). Query
/// values are deliberately excluded: they describe observations/parameters and
/// must not turn an endpoint into a class because a value contains a keyword.
pub fn endpoint_classes(canonical_url: &str) -> BTreeSet<&'static str> {
    let Ok(url) = reqwest::Url::parse(canonical_url) else {
        return BTreeSet::from(["Unknown"]);
    };
    let mut tokens = BTreeSet::new();
    if let Some(host) = url.host_str() {
        tokens.extend(words(host));
    }
    tokens.extend(words(url.path()));

    let mut tags = BTreeSet::new();
    add(
        &mut tags,
        &tokens,
        "Authentication",
        &[
            "auth",
            "authentication",
            "login",
            "logout",
            "signin",
            "signup",
            "oauth",
            "sso",
        ],
    );
    add(
        &mut tags,
        &tokens,
        "UserProfile",
        &["user", "users", "profile", "profiles", "member", "members"],
    );
    add(
        &mut tags,
        &tokens,
        "Account",
        &[
            "account",
            "accounts",
            "tenant",
            "tenants",
            "organization",
            "organizations",
        ],
    );
    add(&mut tags, &tokens, "Admin", &["admin", "administrator"]);
    add(
        &mut tags,
        &tokens,
        "Internal",
        &["internal", "private", "staff"],
    );
    add(
        &mut tags,
        &tokens,
        "Debug",
        &["debug", "trace", "metrics", "actuator"],
    );
    add(&mut tags, &tokens, "Upload", &["upload", "uploads"]);
    add(&mut tags, &tokens, "Download", &["download", "downloads"]);
    add(&mut tags, &tokens, "Export", &["export", "exports"]);
    add(&mut tags, &tokens, "Import", &["import", "imports"]);
    add(
        &mut tags,
        &tokens,
        "Payment",
        &[
            "payment", "payments", "billing", "invoice", "invoices", "checkout",
        ],
    );
    add(
        &mut tags,
        &tokens,
        "Order",
        &["order", "orders", "cart", "carts"],
    );
    add(
        &mut tags,
        &tokens,
        "Document",
        &[
            "document",
            "documents",
            "doc",
            "docs",
            "file",
            "files",
            "pdf",
        ],
    );
    add(&mut tags, &tokens, "Search", &["search", "find"]);
    add(&mut tags, &tokens, "Redirect", &["redirect", "redirects"]);
    add(&mut tags, &tokens, "Webhook", &["webhook", "webhooks"]);
    add(&mut tags, &tokens, "GraphQL", &["graphql", "gql"]);

    if tokens.contains("api")
        || tokens.iter().any(|token| {
            token.strip_prefix('v').is_some_and(|version| {
                !version.is_empty() && version.chars().all(|character| character.is_ascii_digit())
            })
        })
    {
        tags.insert("Api");
    }

    const STATIC_EXTENSIONS: &[&str] = &[
        "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff",
        "woff2", "ttf", "eot",
    ];
    let extension = url
        .path()
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension.to_ascii_lowercase());
    if tokens.contains("assets")
        || tokens.contains("static")
        || extension
            .as_deref()
            .is_some_and(|extension| STATIC_EXTENSIONS.contains(&extension))
    {
        tags.insert("Static");
    }

    if tags.is_empty() {
        tags.insert("Unknown");
    }
    tags
}

/// Normalize separators and ASCII case so snake_case, kebab-case, and common
/// camelCase spellings converge, then use exact aliases only.
pub fn parameter_semantic(name: &str) -> &'static str {
    let value: String = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    let semantic = if [
        "redirect",
        "redirecturi",
        "redirecturl",
        "return",
        "returnurl",
        "returnto",
        "next",
        "continue",
    ]
    .contains(&value.as_str())
    {
        "Redirect"
    } else if ["url", "uri", "endpoint", "target"].contains(&value.as_str()) {
        "Url"
    } else if ["file", "filename"].contains(&value.as_str()) {
        "File"
    } else if ["path", "filepath"].contains(&value.as_str()) {
        "Path"
    } else if ["userid", "uid"].contains(&value.as_str()) {
        "UserId"
    } else if value == "accountid" {
        "AccountId"
    } else if ["id", "objectid"].contains(&value.as_str()) {
        "ObjectId"
    } else if ["q", "search", "keyword"].contains(&value.as_str()) {
        "Search"
    } else if value == "callback" {
        "Callback"
    } else if ["webhook", "webhookurl"].contains(&value.as_str()) {
        "Webhook"
    } else if value == "template" {
        "Template"
    } else if value == "query" {
        "Query"
    } else if ["page", "offset", "limit", "cursor"].contains(&value.as_str()) {
        "Pagination"
    } else {
        "Unknown"
    };
    debug_assert!(PARAMETER_SEMANTICS.contains(&semantic));
    semantic
}

fn words(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
}

fn add(
    tags: &mut BTreeSet<&'static str>,
    tokens: &BTreeSet<String>,
    class: &'static str,
    aliases: &[&str],
) {
    debug_assert!(ENDPOINT_CLASSES.contains(&class));
    if aliases.iter().any(|alias| tokens.contains(*alias)) {
        tags.insert(class);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(path: &str) -> BTreeSet<&'static str> {
        endpoint_classes(&format!("https://example.com{path}"))
    }

    #[test]
    fn endpoint_fixture_matrix_is_multi_tagged_and_conservative() {
        let fixtures: &[(&str, &[&str])] = &[
            ("/api/users/profile", &["Api", "UserProfile"]),
            ("/auth/login", &["Authentication"]),
            ("/admin/internal/debug", &["Admin", "Internal", "Debug"]),
            (
                "/upload/download/export/import",
                &["Upload", "Download", "Export", "Import"],
            ),
            (
                "/payments/orders/documents",
                &["Payment", "Order", "Document"],
            ),
            (
                "/api/search/redirect/webhooks/graphql",
                &["Api", "Search", "Redirect", "Webhook", "GraphQL"],
            ),
            ("/static/app.js", &["Static"]),
            ("/ordinary/health", &["Unknown"]),
        ];
        for (path, expected) in fixtures {
            assert_eq!(classes(path), expected.iter().copied().collect(), "{path}");
        }
        assert_eq!(
            classes("/api/captain/authors/hookah"),
            BTreeSet::from(["Api"])
        );
        assert_eq!(
            classes("/ordinary?next=/admin"),
            BTreeSet::from(["Unknown"])
        );
    }

    #[test]
    fn parameter_fixture_matrix_handles_case_separators_and_ambiguity() {
        let fixtures = [
            ("redirect_uri", "Redirect"),
            ("returnUrl", "Redirect"),
            ("url", "Url"),
            ("file_name", "File"),
            ("filePath", "Path"),
            ("id", "ObjectId"),
            ("user_id", "UserId"),
            ("userId", "UserId"),
            ("account_id", "AccountId"),
            ("accountId", "AccountId"),
            ("q", "Search"),
            ("callback", "Callback"),
            ("webhook_url", "Webhook"),
            ("template", "Template"),
            ("query", "Query"),
            ("cursor", "Pagination"),
            ("identity", "Unknown"),
            ("destination", "Unknown"),
        ];
        for (name, expected) in fixtures {
            assert_eq!(parameter_semantic(name), expected, "{name}");
        }
    }
}
