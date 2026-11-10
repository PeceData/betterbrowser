// Один внешний прокси и туннель через него до host:port (SOCKS5 или HTTP CONNECT).
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use super::head::read_head;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Kind {
    Socks5,
    Http,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Upstream {
    pub kind: Kind,
    pub addr: SocketAddr,
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let scheme = match self.kind {
            Kind::Socks5 => "socks5",
            Kind::Http => "http",
        };
        write!(f, "{scheme}://{}", self.addr)
    }
}

fn fail(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}

impl Upstream {
    // Строка списка: "1.2.3.4:1080" или "socks5://1.2.3.4:1080".
    pub fn parse(kind: Kind, line: &str) -> Option<Self> {
        let addr = line.trim().rsplit("://").next()?;
        Some(Self { kind, addr: addr.parse().ok()? })
    }

    // Имя хоста уходит прокси как есть: DNS решает он, а не провайдер, и подменить адрес нельзя.
    pub fn tunnel(&self, host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
        let mut s = TcpStream::connect_timeout(&self.addr, timeout)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        match self.kind {
            Kind::Socks5 => socks5(&mut s, host, port)?,
            Kind::Http => http_connect(&mut s, host, port)?,
        }
        s.set_read_timeout(None)?;
        s.set_write_timeout(None)?;
        Ok(s)
    }
}

const SOCKS_VERSION: u8 = 5;
const SOCKS_NO_AUTH: u8 = 0;
const SOCKS_CMD_CONNECT: u8 = 1;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;
const SOCKS_OK: u8 = 0;

fn socks5(s: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    s.write_all(&[SOCKS_VERSION, 1, SOCKS_NO_AUTH])?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello)?;
    if hello != [SOCKS_VERSION, SOCKS_NO_AUTH] {
        return Err(fail("socks5 wants auth"));
    }
    let name = host.as_bytes();
    let len = u8::try_from(name.len()).map_err(|_| fail("host too long"))?;
    let mut req = vec![SOCKS_VERSION, SOCKS_CMD_CONNECT, 0, SOCKS_ATYP_DOMAIN, len];
    req.extend_from_slice(name);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    let mut reply = [0u8; 4];
    s.read_exact(&mut reply)?;
    if reply[0] != SOCKS_VERSION || reply[1] != SOCKS_OK {
        return Err(fail("socks5 refused"));
    }
    // Хвост ответа (адрес, к которому прокси подключился) нам не нужен, но его надо дочитать.
    let addr_len = match reply[3] {
        SOCKS_ATYP_IPV4 => 4,
        SOCKS_ATYP_IPV6 => 16,
        SOCKS_ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(fail("socks5 bad reply")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest)
}

fn http_connect(s: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    write!(s, "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")?;
    let head = read_head(s)?;
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(fail("http proxy refused CONNECT"))
    }
}
