// Автоматический VPN: сайты из списка открываются через проверенные бесплатные прокси,
// всё остальное (банки, почта, госуслуги) идёт напрямую.
// Работает через PAC-файл WebView2, поэтому только на Windows. Настройки применяются при запуске.
mod config;
mod head;
mod pool;
mod server;
mod sites;
mod upstream;

use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};

use server::Server;
use sites::Sites;

pub use sites::default_list;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VpnSettings {
    pub enabled: bool,
    pub sites: Vec<String>,
}

impl Default for VpnSettings {
    fn default() -> Self {
        Self { enabled: true, sites: default_list() }
    }
}

static RUNNING: OnceLock<Arc<Server>> = OnceLock::new();

// Вызывать до создания первого webview: аргументы WebView2 задаются один раз на процесс.
pub fn start(settings: &VpnSettings) {
    if !settings.enabled || !cfg!(windows) {
        log::info!("vpn: off");
        return;
    }
    let listener = match server::bind() {
        Ok(l) => l,
        Err(e) => return log::error!("vpn: could not start the local proxy: {e}"),
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => return log::error!("vpn: {e}"),
    };
    let server = Arc::new(Server { sites: Arc::new(Sites::new(&settings.sites)), pool: pool::Pool::start(), port });
    server.clone().run(listener);
    log::info!("vpn: local proxy on port {port}, {} sites", server.sites.domains().len());
    let _ = RUNNING.set(server);
}

// Одинаковые для всех webview — иначе WebView2 откажется их создавать.
pub fn browser_args() -> Option<String> {
    let s = RUNNING.get()?;
    Some(format!(
        "{} --proxy-pac-url=http://{}:{}{}",
        config::WEBVIEW2_DEFAULT_ARGS,
        config::LOCAL_HOST,
        s.port,
        config::PAC_PATH
    ))
}

// Идёт ли этот адрес через VPN — для значка в адресной строке.
pub fn routes(url: &str) -> bool {
    let Some(s) = RUNNING.get() else { return false };
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| s.sites.matches(h))).unwrap_or(false)
}

#[tauri::command]
pub async fn vpn_status() -> serde_json::Value {
    match RUNNING.get() {
        None => serde_json::json!({ "running": false }),
        Some(s) => serde_json::json!({
            "running": true,
            "proxies": s.pool.len(),
            "best": s.pool.candidates().first().map(|u| u.to_string()),
            "checking": s.pool.is_checking(),
        }),
    }
}
