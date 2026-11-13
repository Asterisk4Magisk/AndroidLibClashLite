// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use std::{
    collections::HashMap,
    fs::{self, Metadata},
    path::Path,
    sync::{Arc, LazyLock, Mutex},
};

#[derive(Default)]
struct PackageCache {
    metadata: Option<Metadata>,
    names: HashMap<u32, Arc<str>>,
}

impl PackageCache {
    fn lookup(&mut self, path: &Path, uid: u32) -> Option<Arc<str>> {
        let current = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.metadata = None;
                self.names.clear();
                return None;
            }
        };
        if !self
            .metadata
            .as_ref()
            .is_some_and(|old| same_file(old, &current))
        {
            let file = fs::File::open(path).ok()?;
            let metadata = file.metadata().ok()?;
            let text = std::io::read_to_string(file).ok()?;
            let mut names = HashMap::new();
            for line in text.lines() {
                let mut fields = line.split_whitespace();
                let Some(name) = fields.next() else { continue };
                let Some(uid) = fields.next().and_then(|id| id.parse::<u32>().ok()) else {
                    continue;
                };
                names.entry(uid).or_insert_with(|| Arc::from(name));
            }
            self.metadata = Some(metadata);
            self.names = names;
        }
        self.names.get(&(uid % 100000)).cloned()
    }
}

fn same_file(old: &Metadata, current: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if old.dev() != current.dev() || old.ino() != current.ino() {
            return false;
        }
    }
    old.len() == current.len() && old.modified().ok() == current.modified().ok()
}

pub(super) fn lookup(uid: u32) -> Option<Arc<str>> {
    static PACKAGES: LazyLock<Mutex<PackageCache>> = LazyLock::new(Mutex::default);
    PACKAGES
        .lock()
        .ok()?
        .lookup(Path::new("/data/system/packages.list"), uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_and_multi_user_uid() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("packages.list");
        let mut cache = PackageCache::default();
        assert_eq!(cache.lookup(&path, 1012345), None);
        fs::write(&path, "first 12345 extra\n").unwrap();
        assert_eq!(cache.lookup(&path, 1012345).as_deref(), Some("first"));
        fs::write(&path, "replacement 12345 extra\n").unwrap();
        assert_eq!(cache.lookup(&path, 112345).as_deref(), Some("replacement"));
        fs::remove_file(&path).unwrap();
        assert_eq!(cache.lookup(&path, 1012345), None);
    }
}
