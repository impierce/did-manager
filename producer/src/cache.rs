use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use log::info;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Caches the resolved DID Documents in-memory.
///
/// * **simple**: key-value store where the key is the `DID` and the value is the resolved `DID Document`
/// * **lazy**: the cache does not automatically run any clean up tasks. It evaluates the cache entries only when they are accessed.
///
/// NOTE: Use with caution! Caches can hold outdated data. A short TTL is recommended.
#[derive(Debug)]
pub struct InMemoryCache {
    entries: HashMap<CoreDID, CacheEntry>,
    pub include: Vec<CoreDID>,
    pub ttl: u64,
}

pub struct InMemoryCacheBuilder {
    include: Vec<CoreDID>,
    ttl: u64,
}

impl Default for InMemoryCacheBuilder {
    fn default() -> InMemoryCacheBuilder {
        InMemoryCacheBuilder {
            include: Vec::new(),
            ttl: 5_000,
        }
    }
}

#[derive(Debug)]
struct CacheEntry {
    document: CoreDocument,
    expires_at: Instant,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            include: Vec::new(),
            ttl: 5_000,
        }
    }

    pub fn builder() -> InMemoryCacheBuilder {
        InMemoryCacheBuilder::default()
    }

    pub fn insert(&mut self, document: CoreDocument) {
        let expires_at = Instant::now() + Duration::from_millis(self.ttl);
        if !self.include.is_empty() && !self.include.contains(document.id()) {
            return;
        }
        let entry = CacheEntry {
            document: document.clone(),
            expires_at,
        };
        match self.entries.insert(document.id().clone(), entry) {
            Some(_) => info!("[*] Existing cache entry updated: `{:?}`", document.id()),
            None => info!("[+] New cache entry inserted: `{:?}`", document.id()),
        };
    }

    /// Retrieves a DID Document from the cache. If it exists, but is expired, then remove it.
    pub fn retrieve(&mut self, did: &CoreDID) -> Option<CoreDocument> {
        let entry = self.entries.get(did)?;

        if entry.expires_at < Instant::now() {
            if self.entries.remove(did).is_some() {
                info!("[-] Expired cache entry removed: `{:?}`", did)
            }
            return None;
        }

        info!("[!] Retrieved DID document from cache for DID `{:?}`", did);
        Some(entry.document.clone())
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCacheBuilder {
    /// Sets the list of DIDs to be included in the cache.
    ///
    /// If the `include` list is not empty, only the specified DIDs are cached.
    ///
    /// If the `include` list is empty, all DID documents are cached.
    pub fn include(mut self, include: Vec<CoreDID>) -> Self {
        self.include = include;
        self
    }

    /// Sets the time-to-live (TTL) for cached DID documents in milliseconds.
    pub fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn build(self) -> InMemoryCache {
        InMemoryCache {
            entries: HashMap::new(),
            include: self.include,
            ttl: self.ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    #[test(tokio::test)]
    async fn new_cache_has_expected_defaults() {
        let cache = InMemoryCache::new();

        assert_eq!(cache.include.len(), 0);
        assert_eq!(cache.ttl, 5_000);
    }

    #[test(tokio::test)]
    async fn successfully_inserts_new_cache_entry() {
        let mut cache = InMemoryCache::new();
        let did = CoreDID::parse("did:example:123").unwrap();
        let document = CoreDocument::builder(Default::default())
            .id(did.clone())
            .build()
            .unwrap();
        cache.insert(document.clone());

        assert_eq!(cache.retrieve(&did), Some(document));
    }

    #[test(tokio::test)]
    async fn expired_entry_is_not_retrieved_but_lazily_removed() {
        let mut cache = InMemoryCache::builder().build();
        let did = CoreDID::parse("did:example:123").unwrap();
        let document = CoreDocument::builder(Default::default())
            .id(did.clone())
            .build()
            .unwrap();

        let expired_entry = CacheEntry {
            document,
            expires_at: Instant::now() - Duration::from_millis(1_000),
        };

        cache.entries.insert(did.clone(), expired_entry);

        assert!(cache.entries.contains_key(&did));
        assert_eq!(cache.retrieve(&did), None);
        assert!(cache.entries.is_empty());
    }

    #[test(tokio::test)]
    async fn entry_that_has_not_expired_is_retrieved() {
        let mut cache = InMemoryCache::builder().ttl(5_000).build();
        let did = CoreDID::parse("did:example:123").unwrap();
        let document = CoreDocument::builder(Default::default())
            .id(did.clone())
            .build()
            .unwrap();

        let expired_entry = CacheEntry {
            document: document.clone(),
            expires_at: Instant::now() + Duration::from_millis(6_000),
        };

        cache.entries.insert(did.clone(), expired_entry);

        assert!(cache.entries.contains_key(&did));
        assert_eq!(cache.retrieve(&did), Some(document));
        assert!(cache.entries.contains_key(&did));
    }

    #[test(tokio::test)]
    async fn when_included_matches_then_entry_is_retrieved() {
        let mut cache = InMemoryCache::builder()
            .include(vec![CoreDID::parse("did:example:123").unwrap()])
            .build();
        let did = CoreDID::parse("did:example:123").unwrap();
        let document = CoreDocument::builder(Default::default())
            .id(did.clone())
            .build()
            .unwrap();
        cache.insert(document.clone());

        assert!(cache.entries.get(&did).is_some());
    }

    #[test(tokio::test)]
    async fn when_included_not_matches_then_entry_is_not_inserted() {
        let mut cache = InMemoryCache::builder()
            .include(vec![CoreDID::parse("did:example:123").unwrap()])
            .build();
        let did = CoreDID::parse("did:foo:bar").unwrap();
        let document = CoreDocument::builder(Default::default())
            .id(did.clone())
            .build()
            .unwrap();
        cache.insert(document.clone());

        assert!(cache.entries.is_empty());
    }
}
