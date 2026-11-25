// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicU32, Ordering::SeqCst},
        Mutex, OnceLock,
    },
};

const LEGACY_MAGIC: u32 = 0x3144_4955;
const MAGIC: u32 = 0x3244_4955;
const SLOTS: usize = 2048;
const WORDS: usize = 6;
const SIZE: usize = 4 * (2 + SLOTS * WORDS);
const TTL_MS: u32 = 5000;
static TABLE: OnceLock<&'static [AtomicU32]> = OnceLock::new();
static DEMAND: OnceLock<&'static AtomicU32> = OnceLock::new();
static SUBSCRIBERS: Mutex<usize> = Mutex::new(0);

pub(crate) fn install() {
    let Some((table_fd, demand_fd)) = std::env::var("ASTERISK_DNS_OBSERVATION_FDS")
        .ok()
        .and_then(|text| {
            let (table, demand) = text.split_once(':')?;
            Some((table.parse::<i32>().ok()?, demand.parse::<i32>().ok()?))
        })
        .filter(|&(table, demand)| table >= 3 && demand >= 3 && table != demand)
    else {
        return;
    };
    let fd = unsafe { OwnedFd::from_raw_fd(table_fd) };
    let demand_fd = unsafe { OwnedFd::from_raw_fd(demand_fd) };
    let mut info = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut info) } != 0
        || info.st_size as usize != SIZE
        || unsafe { libc::fstat(demand_fd.as_raw_fd(), &mut info) } != 0
        || info.st_size as usize != size_of::<AtomicU32>()
    {
        return;
    }
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SIZE,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if memory == libc::MAP_FAILED {
        return;
    }
    let table = unsafe { std::slice::from_raw_parts(memory.cast::<AtomicU32>(), SIZE / 4) };
    if !matches!(table[0].load(SeqCst), MAGIC | LEGACY_MAGIC) {
        unsafe { libc::munmap(memory, SIZE) };
        return;
    }
    let demand = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size_of::<AtomicU32>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            demand_fd.as_raw_fd(),
            0,
        )
    };
    if demand == libc::MAP_FAILED || TABLE.set(table).is_err() {
        unsafe { libc::munmap(memory, SIZE) };
        if demand != libc::MAP_FAILED {
            unsafe { libc::munmap(demand, size_of::<AtomicU32>()) };
        }
        return;
    }
    let _ = DEMAND.set(unsafe { &*demand.cast::<AtomicU32>() });
    meow_dns::events::set_enhanced_uid_lookup(lookup);
}

pub(crate) struct Observation(Option<&'static AtomicU32>);

pub(crate) fn observe() -> Observation {
    let demand = DEMAND.get().copied();
    if let Some(demand) = demand {
        let mut subscribers = SUBSCRIBERS.lock().expect("DNS UID observation");
        *subscribers += 1;
        if *subscribers == 1 {
            demand.store(1, SeqCst);
        }
    }
    Observation(demand)
}

impl Drop for Observation {
    fn drop(&mut self) {
        if let Some(demand) = self.0 {
            let mut subscribers = SUBSCRIBERS.lock().expect("DNS UID observation");
            *subscribers -= 1;
            if *subscribers == 0 {
                demand.store(0, SeqCst);
            }
        }
    }
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for &byte in bytes {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211);
    }
}

fn lookup(tcp: bool, source: SocketAddr, destination: SocketAddr, request: &[u8]) -> Option<u32> {
    let table = TABLE.get()?;
    let epoch = table[1].load(SeqCst);
    if epoch == 0 || source.port() == 0 || destination.port() != 53 || request.len() < 12 {
        return None;
    }
    let mut hash = 14_695_981_039_346_656_037;
    hash_bytes(&mut hash, &[if tcp { 6 } else { 17 }]);
    for endpoint in [source, destination] {
        match endpoint.ip().to_canonical() {
            std::net::IpAddr::V4(address) => {
                hash_bytes(&mut hash, &[4]);
                hash_bytes(&mut hash, &address.octets());
            }
            std::net::IpAddr::V6(address) => {
                hash_bytes(&mut hash, &[6]);
                hash_bytes(&mut hash, &address.octets());
            }
        }
        hash_bytes(&mut hash, &endpoint.port().to_be_bytes());
    }
    let request = if tcp || table[0].load(SeqCst) == LEGACY_MAGIC {
        request
    } else {
        &request[2..]
    };
    hash_bytes(&mut hash, request);
    let entry = &table[2 + (hash as usize & (SLOTS - 1)) * WORDS..];
    let sequence = entry[0].load(SeqCst);
    if sequence & 1 != 0
        || entry[1].load(SeqCst) != epoch
        || entry[3].load(SeqCst) != hash as u32
        || entry[4].load(SeqCst) != (hash >> 32) as u32
    {
        return None;
    }
    let timestamp = entry[2].load(SeqCst);
    let uid = entry[5].load(SeqCst);
    let mut now = unsafe { std::mem::zeroed::<libc::timespec>() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return None;
    }
    let ms = (now.tv_sec as u64 * 1000 + now.tv_nsec as u64 / 1_000_000) as u32;
    (ms.wrapping_sub(timestamp) <= TTL_MS
        && entry[0].load(SeqCst) == sequence
        && table[1].load(SeqCst) == epoch)
        .then_some(uid)
}
