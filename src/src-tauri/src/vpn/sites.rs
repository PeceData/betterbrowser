// Список сайтов, которые идут через прокси. Всё остальное — напрямую.
const DEFAULT_SITES: &str = include_str!("default_sites.txt");

pub fn default_list() -> Vec<String> {
    DEFAULT_SITES.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

pub struct Sites(Vec<String>);

impl Sites {
    pub fn new(raw: &[String]) -> Self {
        let mut list: Vec<String> = raw.iter().filter_map(|s| normalize(s)).collect();
        list.sort();
        list.dedup();
        Self(list)
    }

    pub fn domains(&self) -> &[String] {
        &self.0
    }

    // Домен и все его поддомены: "youtube.com" ловит и "www.youtube.com".
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.0.iter().any(|d| host == *d || host.strip_suffix(d.as_str()).is_some_and(|p| p.ends_with('.')))
    }
}

// Принимаем и то, что люди обычно вставляют: "https://www.site.com/path", "*.site.com".
fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    let s = s.split("://").last()?;
    let s = s.split(['/', '?', '#']).next()?;
    let s = s.split(':').next()?;
    let s = s.trim_start_matches("*.").trim_start_matches("www.").trim_matches('.');
    let valid = !s.is_empty() && s.contains('.') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    valid.then(|| s.to_string())
}
