// Пул проверенных бесплатных прокси: скачивает списки, проверяет, держит лучшие и меняет мёртвые.
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::config::*;
use super::upstream::Upstream;

#[derive(Clone)]
struct Good {
    up: Upstream,
    latency: Duration,
}

pub struct Pool {
    good: Mutex<Vec<Good>>,
    checking: AtomicBool,
    kick: Mutex<Sender<()>>,
}

impl Pool {
    pub fn start() -> Arc<Self> {
        let (tx, rx) = channel();
        let pool = Arc::new(Self { good: Mutex::new(Vec::new()), checking: AtomicBool::new(false), kick: Mutex::new(tx) });
        let p = pool.clone();
        thread::spawn(move || p.maintain(rx));
        pool
    }

    // Лучшие прокси, самый быстрый первым.
    pub fn candidates(&self) -> Vec<Upstream> {
        self.good.lock().unwrap().iter().map(|g| g.up.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.good.lock().unwrap().len()
    }

    pub fn is_checking(&self) -> bool {
        self.checking.load(Ordering::Relaxed)
    }

    // Прокси перестал отвечать: выкидываем и, если осталось мало, будим поиск новых.
    pub fn drop_dead(&self, up: &Upstream) {
        let left = {
            let mut good = self.good.lock().unwrap();
            good.retain(|g| g.up != *up);
            good.len()
        };
        log::info!("vpn: {up} stopped working, {left} left");
        if left < POOL_MIN {
            let _ = self.kick.lock().unwrap().send(());
        }
    }

    fn maintain(&self, rx: Receiver<()>) {
        loop {
            self.checking.store(true, Ordering::Relaxed);
            self.recheck();
            if self.len() < POOL_MIN {
                self.refill();
            }
            self.checking.store(false, Ordering::Relaxed);
            let wait = if self.len() == 0 { RETRY_WHEN_EMPTY } else { RECHECK_EVERY };
            let _ = rx.recv_timeout(wait);
            // Несколько пинков подряд — одна проверка.
            while rx.try_recv().is_ok() {}
        }
    }

    // Старые прокси могли умереть: проверяем заново и сортируем по скорости.
    fn recheck(&self) {
        let current: Vec<Upstream> = self.candidates();
        if current.is_empty() {
            return;
        }
        let mut alive: Vec<Good> =
            current.into_iter().filter_map(|up| probe(&up).map(|latency| Good { up, latency })).collect();
        alive.sort_by_key(|g| g.latency);
        *self.good.lock().unwrap() = alive;
    }

    fn refill(&self) {
        let known: HashSet<Upstream> = self.candidates().into_iter().collect();
        let mut list: Vec<Upstream> = fetch_all().into_iter().filter(|u| !known.contains(u)).collect();
        shuffle(&mut list);
        list.truncate(MAX_CANDIDATES);
        log::info!("vpn: checking {} free proxies", list.len());

        let queue = Arc::new(Mutex::new(list.into_iter()));
        let found = Arc::new(Mutex::new(Vec::<Good>::new()));
        let have = Arc::new(AtomicUsize::new(known.len()));
        let workers: Vec<_> = (0..CHECK_WORKERS)
            .map(|_| {
                let (queue, found, have) = (queue.clone(), found.clone(), have.clone());
                thread::spawn(move || {
                    while have.load(Ordering::Relaxed) < POOL_TARGET {
                        let Some(up) = queue.lock().unwrap().next() else { break };
                        if let Some(latency) = probe(&up) {
                            have.fetch_add(1, Ordering::Relaxed);
                            found.lock().unwrap().push(Good { up, latency });
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            let _ = w.join();
        }

        let mut good = self.good.lock().unwrap();
        good.extend(found.lock().unwrap().drain(..));
        good.sort_by_key(|g| g.latency);
        log::info!("vpn: {} working proxies, best {:?}", good.len(), good.first().map(|g| g.up.to_string()));
    }
}

fn fetch_all() -> Vec<Upstream> {
    // ureq собран без встроенного TLS, поэтому подключаем системный (как в остальном коде).
    let Ok(tls) = native_tls::TlsConnector::new() else { return Vec::new() };
    let agent = ureq::AgentBuilder::new().tls_connector(Arc::new(tls)).timeout(FETCH_TIMEOUT).build();
    let mut seen = HashSet::new();
    let mut all = Vec::new();
    for (kind, url) in SOURCES {
        let body = match agent.get(url).call().and_then(|r| Ok(r.into_string()?)) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("vpn: could not load {url}: {e}");
                continue;
            }
        };
        for up in body.lines().filter_map(|l| Upstream::parse(*kind, l)) {
            if seen.insert(up.clone()) {
                all.push(up);
            }
        }
    }
    all
}

// Настоящий запрос к заблокированному сайту через прокси с проверкой TLS-сертификата.
// Прокси, который подменяет трафик, проверку сертификата не пройдёт.
fn probe(up: &Upstream) -> Option<Duration> {
    let start = Instant::now();
    let tcp = up.tunnel(CHECK_HOST, HTTPS_PORT, CONNECT_TIMEOUT).ok()?;
    tcp.set_read_timeout(Some(CHECK_TIMEOUT)).ok()?;
    tcp.set_write_timeout(Some(CHECK_TIMEOUT)).ok()?;
    let mut tls = native_tls::TlsConnector::new().ok()?.connect(CHECK_HOST, tcp).ok()?;
    write!(tls, "HEAD / HTTP/1.1\r\nHost: {CHECK_HOST}\r\nConnection: close\r\n\r\n").ok()?;
    let mut status = [0u8; 8];
    tls.read_exact(&mut status).ok()?;
    (&status[..7] == b"HTTP/1.").then(|| start.elapsed())
}

// Перемешиваем, чтобы не проверять каждый раз одни и те же мёртвые прокси из начала списка.
fn shuffle<T>(v: &mut [T]) {
    let mut seed = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1) | 1;
    for i in (1..v.len()).rev() {
        // xorshift: случайности хватает, отдельный крейт не нужен.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        v.swap(i, (seed % (i as u64 + 1)) as usize);
    }
}
