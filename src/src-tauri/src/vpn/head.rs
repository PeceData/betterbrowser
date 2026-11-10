// Чтение заголовка HTTP-запроса или ответа до пустой строки.
use std::io::{self, Read};

use super::config::MAX_HEAD_BYTES;

// Читаем по байту: после заголовка в сокете уже может идти туннель, его трогать нельзя.
pub fn read_head(s: &mut impl Read) -> io::Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "header too long"));
        }
        if s.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.push(byte[0]);
    }
    String::from_utf8(buf).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "header is not utf-8"))
}
