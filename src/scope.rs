use crate::normalize::NormalizedHostname;

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
        if self.allowed_roots.is_empty() {
            return true;
        }

        let cand_str = candidate.as_str();
        for root in &self.allowed_roots {
            let root_str = root.as_str();
            if cand_str == root_str || cand_str.ends_with(&format!(".{}", root_str)) {
                return true;
            }
        }

        false
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
    }
}
