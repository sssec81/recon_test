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
    // Exact hostname labels are strong recon structure (`admin.example.com`).
    // Path compounds are split only when they are short and outside content
    // trees, so `user-profile` works without reviving long editorial slugs.
    let content_route = is_content_url(&url);
    let segments: Vec<String> = path_segments(&url).collect();
    let mut tokens: BTreeSet<String> = segments.iter().cloned().collect();
    if let Some(host) = url.host_str() {
        tokens.extend(host.split('.').map(str::to_ascii_lowercase));
    }
    if !content_route {
        for segment in &segments {
            tokens.extend(short_compound_words(segment));
        }
    }

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

fn path_segments(url: &reqwest::Url) -> impl Iterator<Item = String> + '_ {
    url.path_segments()
        .into_iter()
        .flatten()
        .filter(|segment| !segment.is_empty())
        .map(str::to_ascii_lowercase)
}

fn short_compound_words(segment: &str) -> impl Iterator<Item = String> + '_ {
    let parts: Vec<&str> = segment
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .collect();
    let structural = parts.len() == 2
        && segment.len() <= 24
        && parts.iter().all(|part| {
            part.len() <= 12
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        });
    parts
        .into_iter()
        .filter(move |_| structural)
        .map(str::to_ascii_lowercase)
}

/// Public documentation and editorial routes need stronger evidence than
/// words embedded in their titles before they become security opportunities.
pub fn is_content_route(canonical_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(canonical_url) else {
        return false;
    };
    is_content_url(&url)
}

fn is_content_url(url: &reqwest::Url) -> bool {
    path_segments(url).any(|segment| {
        matches!(
            segment.as_str(),
            "article"
                | "articles"
                | "blog"
                | "blogs"
                | "category"
                | "categories"
                | "docs"
                | "documentation"
                | "help"
                | "hc"
                | "kb"
                | "news"
                | "section"
                | "sections"
                | "support"
        )
    })
}

/// Infer a path identifier only when it follows a resource collection with
/// clear application meaning. Numeric CMS/category/article IDs are content,
/// not authorization evidence.
pub fn path_identifier_name(canonical_url: &str) -> Option<&'static str> {
    if is_content_route(canonical_url) {
        return None;
    }
    let url = reqwest::Url::parse(canonical_url).ok()?;
    let segments: Vec<String> = path_segments(&url).collect();
    for pair in segments.windows(2) {
        let resource = pair[0].as_str();
        let value = pair[1].as_str();
        let meaningful_resource = matches!(
            resource,
            "account"
                | "accounts"
                | "customer"
                | "customers"
                | "document"
                | "documents"
                | "file"
                | "files"
                | "invoice"
                | "invoices"
                | "item"
                | "items"
                | "member"
                | "members"
                | "object"
                | "objects"
                | "order"
                | "orders"
                | "organization"
                | "organizations"
                | "payment"
                | "payments"
                | "project"
                | "projects"
                | "resource"
                | "resources"
                | "tenant"
                | "tenants"
                | "user"
                | "users"
        );
        if meaningful_resource {
            if !value.is_empty() && value.chars().all(|character| character.is_ascii_digit()) {
                return Some("path_id");
            }
            if uuid::Uuid::parse_str(value).is_ok() {
                return Some("path_uuid");
            }
        }
    }
    None
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
    fn content_slugs_do_not_create_functional_security_classes() {
        assert_eq!(
            classes("/hc/en-us/articles/12345-how-to-use-mfa-sso-login"),
            BTreeSet::from(["Unknown"])
        );
        assert_eq!(
            classes("/help/articles/987-zip-download-account-document"),
            BTreeSet::from(["Unknown"])
        );
        assert_eq!(classes("/auth/login"), BTreeSet::from(["Authentication"]));
        assert_eq!(
            classes("/api/users/123"),
            BTreeSet::from(["Api", "UserProfile"])
        );
    }

    #[test]
    fn exact_hostname_labels_and_short_route_compounds_are_structural() {
        let fixtures = [
            ("https://admin.example.com/", &["Admin"][..]),
            ("https://api.example.com/", &["Api"]),
            ("https://auth.example.com/", &["Authentication"]),
            ("https://accounts.example.com/", &["Account"]),
            ("https://graphql.example.com/", &["GraphQL"]),
            ("https://upload.example.com/", &["Upload"]),
            (
                "https://example.com/api/user-profile",
                &["Api", "UserProfile"],
            ),
            (
                "https://example.com/api/file-upload",
                &["Api", "Document", "Upload"],
            ),
            (
                "https://example.com/api/oauth-login",
                &["Api", "Authentication"],
            ),
        ];
        for (url, expected) in fixtures {
            assert_eq!(
                endpoint_classes(url),
                expected.iter().copied().collect(),
                "{url}"
            );
        }
        assert_eq!(
            endpoint_classes("https://example.com/help/file-upload"),
            BTreeSet::from(["Unknown"])
        );
    }

    #[test]
    fn path_identifiers_require_meaningful_non_content_resource_context() {
        assert_eq!(
            path_identifier_name("https://example.com/users/123"),
            Some("path_id")
        );
        assert_eq!(
            path_identifier_name(
                "https://example.com/api/orders/550e8400-e29b-41d4-a716-446655440000"
            ),
            Some("path_uuid")
        );
        assert_eq!(
            path_identifier_name("https://example.com/categories/123"),
            None
        );
        assert_eq!(
            path_identifier_name("https://example.com/hc/articles/123/login"),
            None
        );
        assert_eq!(
            path_identifier_name("https://example.com/releases/2026"),
            None
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
