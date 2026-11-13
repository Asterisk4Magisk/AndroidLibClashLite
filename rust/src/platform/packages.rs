// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use std::{
    collections::HashMap,
    fs::{self, Metadata},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex, OnceLock, RwLock,
    },
};

type Names = HashMap<u32, Arc<str>>;
struct WatchedNames {
    names: RwLock<Names>,
    active: AtomicBool,
}
static WATCHED: OnceLock<Option<Arc<WatchedNames>>> = OnceLock::new();

pub(super) fn cached(uid: u32) -> Option<Option<Arc<str>>> {
    let names = WATCHED.get()?.as_ref()?;
    if !names.active.load(Ordering::Acquire) {
        return None;
    }
    Some(names.names.read().ok()?.get(&(uid % 100000)).cloned())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn watch() -> Option<Arc<WatchedNames>> {
    use std::{ffi::CString, io::Read, os::fd::FromRawFd};
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let directory = CString::new("/data/system").ok()?;
    let mask = libc::IN_CLOSE_WRITE
        | libc::IN_MOVED_TO
        | libc::IN_MOVED_FROM
        | libc::IN_DELETE
        | libc::IN_ATTRIB;
    if unsafe { libc::inotify_add_watch(fd, directory.as_ptr(), mask) } < 0 {
        return None;
    }
    let names = Arc::new(WatchedNames {
        names: RwLock::new(read_names()),
        active: AtomicBool::new(true),
    });
    let updates = names.clone();
    std::thread::Builder::new()
        .name("package-events".into())
        .spawn(move || {
            let mut bytes = [0u8; 4096];
            while let Ok(size) = file.read(&mut bytes) {
                if size == 0 {
                    break;
                }
                let mut offset = 0;
                let mut refresh = false;
                while offset + std::mem::size_of::<libc::inotify_event>() <= size {
                    let event = unsafe {
                        std::ptr::read_unaligned(
                            bytes.as_ptr().add(offset).cast::<libc::inotify_event>(),
                        )
                    };
                    let start = offset + std::mem::size_of::<libc::inotify_event>();
                    let end = start + event.len as usize;
                    if end > size {
                        break;
                    }
                    let name = bytes[start..end]
                        .split(|b| *b == 0)
                        .next()
                        .unwrap_or_default();
                    refresh |= event.mask & libc::IN_Q_OVERFLOW != 0 || name == b"packages.list";
                    offset = end;
                }
                if refresh {
                    *updates.names.write().unwrap() = read_names();
                }
            }
            updates.active.store(false, Ordering::Release);
        })
        .ok()?;
    Some(names)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn watch() -> Option<Arc<WatchedNames>> {
    None
}

fn read_names() -> Names {
    let mut names = HashMap::new();
    if let Ok(text) = fs::read_to_string("/data/system/packages.list") {
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let Some(name) = fields.next() else { continue };
            let Some(uid) = fields.next().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            names.entry(uid).or_insert_with(|| Arc::from(name));
        }
    }
    names
}

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
    WATCHED.get_or_init(watch);
    if let Some(name) = cached(uid) {
        return name;
    }
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
