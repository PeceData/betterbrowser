// Все настройки VPN в одном месте: таймауты, размеры пула, источники прокси.
use std::time::Duration;

use super::upstream::Kind;

// Локальный прокси, через который WebView2 пускает сайты из списка.
// Постоянный порт, чтобы аргументы WebView2 совпадали между запусками.
pub const LOCAL_HOST: &str = "127.0.0.1";
pub const PREFERRED_PORT: u16 = 47_821;
pub const PAC_PATH: &str = "/proxy.pac";

// Через прокси пускаем только HTTPS: шифрование не даёт владельцу прокси подменить страницу.
pub const HTTPS_PORT: u16 = 443;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// Живому трафику даём больше времени, чем проверке: бесплатные прокси бывают медленными.
pub const TUNNEL_TIMEOUT: Duration = Duration::from_secs(10);
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

// Проверка: через прокси открываем заблокированный сайт по HTTPS с проверкой сертификата.
// Прошло — прокси рабочий, умеет обходить блокировку и не подменяет трафик.
pub const CHECK_HOST: &str = "www.instagram.com";

pub const CHECK_WORKERS: usize = 48;
// Сколько рабочих прокси держать про запас и когда искать новые.
pub const POOL_TARGET: usize = 6;
pub const POOL_MIN: usize = 2;
// Больше проверять бессмысленно: рабочие находятся среди первых сотен.
pub const MAX_CANDIDATES: usize = 3000;
pub const RECHECK_EVERY: Duration = Duration::from_secs(10 * 60);
pub const RETRY_WHEN_EMPTY: Duration = Duration::from_secs(60);
// Сколько прокси из пула пробовать на одно соединение, прежде чем сдаться.
pub const TUNNEL_ATTEMPTS: usize = 3;
// Одна неудача — ещё не смерть прокси (сайт не ответил, сеть дёрнулась). Выкидываем после стольких подряд.
pub const MAX_FAILURES: u32 = 3;

pub const MAX_HEAD_BYTES: usize = 16 * 1024;

// Открытые списки бесплатных прокси, обновляются их авторами несколько раз в день.
pub const SOURCES: &[(Kind, &str)] = &[
    (Kind::Socks5, "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    (Kind::Socks5, "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
    (Kind::Socks5, "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"),
    (Kind::Http, "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    (Kind::Http, "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    (Kind::Http, "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
];

// Аргументы, которые wry передаёт WebView2 по умолчанию: свои аргументы их заменяют, а не дополняют.
pub const WEBVIEW2_DEFAULT_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";
