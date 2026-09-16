use crate::scan::normalize::NormalizedHostname;

#[derive(Debug, Clone)]
pub struct ScopePolicy {
    pub allowed_roots: Vec<NormalizedHostname>,
}

impl ScopePolicy {
    pub fn new(roots: Vec<String>) -> Self {
        let allowed_roots = roots
            .into_iter()
            .filter_map(|r| NormalizedHostname::new(&r))
            .collect();
        Self { allowed_roots }
    }

    pub fn is_in_scope(&self, candidate: &NormalizedHostname) -> bool {
        let cand_str = candidate.as_str();
        for root in &self.allowed_roots {
            let root_str = root.as_str();
            if cand_str == root_str || cand_str.ends_with(&format!(".{}", root_str)) {
                return true;
            }
        }

        false
    }

    pub fn allows_redirect_url(&self, url: &reqwest::Url) -> bool {
        url.host_str()
            .and_then(NormalizedHostname::new)
            .is_some_and(|host| self.is_in_scope(&host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_policy() {
        let policy = ScopePolicy::new(vec!["example.com".to_string()]);
        let in_scope = NormalizedHostname::new("sub.example.com").unwrap();
        let out_scope = NormalizedHostname::new("evil.com").unwrap();
        let root_exact = NormalizedHostname::new("example.com").unwrap();

        assert!(policy.is_in_scope(&in_scope));
        assert!(policy.is_in_scope(&root_exact));
        assert!(!policy.is_in_scope(&out_scope));

        let empty_policy = ScopePolicy::new(vec![" ".to_string()]);
        assert!(!empty_policy.is_in_scope(&in_scope));
    }

    #[test]
    fn test_redirect_scope() {
        let policy = ScopePolicy::new(vec!["example.com".to_string()]);
        assert!(policy.allows_redirect_url(&"https://app.example.com/login".parse().unwrap()));
        assert!(!policy.allows_redirect_url(&"https://other.example.org/".parse().unwrap()));
        assert!(!policy.allows_redirect_url(&"https://example.com.evil.org/".parse().unwrap()));
    }
}
