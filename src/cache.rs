use parking_lot::RwLock;
use std::{
    collections::HashMap,
    path::PathBuf,
    time::SystemTime,
};

use crate::htaccess::rules::HtAccess;

pub struct Cached {
    pub mtime: SystemTime,
    pub rules: HtAccess,
}

pub struct HtCache {
    inner: RwLock<HashMap<PathBuf, Cached>>,
}

impl HtCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, path: &PathBuf) -> Option<Cached> {
        self.inner.read().get(path).cloned()
    }

    pub fn insert(&self, path: PathBuf, value: Cached) {
        self.inner.write().insert(path, value);
    }
}

