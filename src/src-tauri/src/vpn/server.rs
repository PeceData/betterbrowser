// Локальный прокси на 127.0.0.1. WebView2 узнаёт о нём из PAC-файла и шлёт сюда
// только сайты из списка. Здесь HTTPS уходит в туннель через бесплатный прокси,
// а HTTP переадресуется на HTTPS — открытым текстом через чужой прокси ничего не идёт.
use std::io::{self, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use super::config::*;
use super::head::read_head;
use super::pool::Pool;
use super::sites::Sites;

pub struct Server {
    pub sites: Arc<Sites>,
    pub pool: Arc<Pool>,
    pub port: u16,
}

pub fn bind() -> io::Result<TcpListener> {
    TcpListener::bind((LOCAL_HOST, PREFERRED_PORT)).or_else(|e| {
        log::warn!("vpn: port {PREFERRED_PORT} is busy ({e}), taking any free one");
        TcpListener::bind((LOCAL_HOST, 0))
    })
}

impl Server {
    pub fn run(self: Arc<Self>, listener: TcpListener) {
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let me = self.clone();
                thread::spawn(move || {
                    if let Err(e) = me.handle(conn) {
                        log::debug!("vpn: connection ended: {e}");
                    }
                });
            }
        });
    }

    fn handle(&self, mut client: TcpStream) -> io::Result<()> {
        let head = read_head(&mut client)?;
        let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
        let (method, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());

        if method == "GET" && target == PAC_PATH {
            log::info!("vpn: browser loaded the PAC file");
            return respond(&mut client, "200 OK", "application/x-ns-proxy-autoconfig", &self.pac());
        }
        if method == "CONNECT" {
            return self.connect(client, target);
        }
        // Обычный HTTP к сайту из списка: отправляем браузер на HTTPS-версию.
        if let Some(rest) = target.strip_prefix("http://") {
            let host = rest.split(['/', ':']).next().unwrap_or_default();
            if self.sites.matches(host) {
                let location = format!("https://{rest}");
                write!(client, "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            }
        }
        respond(&mut client, "403 Forbidden", "text/plain", "Not routed through VPN")
    }

    fn connect(&self, mut client: TcpStream, target: &str) -> io::Result<()> {
        let (host, port) = target.rsplit_once(':').unwrap_or((target, ""));
        let port: u16 = port.parse().unwrap_or(0);
        // Только HTTPS и только сайты из списка: остальное через чужой прокси не пускаем.
        if port != HTTPS_PORT || !self.sites.matches(host) {
            return respond(&mut client, "403 Forbidden", "text/plain", "Only HTTPS to listed sites");
        }
        for up in self.pool.candidates().into_iter().take(TUNNEL_ATTEMPTS) {
            match up.tunnel(host, port, CONNECT_TIMEOUT) {
                Ok(remote) => {
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    return pipe(client, remote);
                }
                Err(_) => self.pool.drop_dead(&up),
            }
        }
        respond(&mut client, "502 Bad Gateway", "text/plain", "No working free proxy right now, try again in a minute")
    }

    // PAC — маленький скрипт, по которому браузер решает, куда слать каждый сайт.
    fn pac(&self) -> String {
        let list = serde_json::to_string(self.sites.domains()).unwrap_or_else(|_| "[]".into());
        format!(
            "var SITES = {list};\n\
             function FindProxyForURL(url, host) {{\n\
               host = host.toLowerCase();\n\
               for (var i = 0; i < SITES.length; i++) {{\n\
                 if (host == SITES[i] || dnsDomainIs(host, '.' + SITES[i])) return 'PROXY {LOCAL_HOST}:{port}';\n\
               }}\n\
               return 'DIRECT';\n\
             }}\n",
            port = self.port
        )
    }
}

fn respond(c: &mut TcpStream, status: &str, kind: &str, body: &str) -> io::Result<()> {
    write!(
        c,
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

// Гоним байты в обе стороны, пока одна из сторон не закроет соединение.
fn pipe(client: TcpStream, remote: TcpStream) -> io::Result<()> {
    let (mut c_read, mut r_write) = (client.try_clone()?, remote.try_clone()?);
    let upload = thread::spawn(move || {
        let _ = io::copy(&mut c_read, &mut r_write);
        let _ = r_write.shutdown(Shutdown::Write);
    });
    let (mut r_read, mut c_write) = (remote, client);
    let _ = io::copy(&mut r_read, &mut c_write);
    let _ = c_write.shutdown(Shutdown::Write);
    let _ = upload.join();
    Ok(())
}
