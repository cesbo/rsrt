/// A parsed `srt://host:port?key=value&...` URL. Plain `std` parsing: no
/// percent-decoding, no IPv6 brackets (the library is IPv4-only).
pub struct SrtUrl {
    host: String,
    port: u16,
    params: Vec<(String, String)>,
}

impl SrtUrl {
    pub fn parse(s: &str) -> Result<SrtUrl, String> {
        let rest = s
            .strip_prefix("srt://")
            .ok_or_else(|| format!("not an srt:// URL: {s}"))?;
        let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| format!("missing port in {addr:?}"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("invalid port in {addr:?}"))?;
        let params = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (pair.to_string(), String::new()),
            })
            .collect();

        let host = if host.is_empty() {
            "0.0.0.0".to_owned()
        } else {
            host.to_owned()
        };

        Ok(SrtUrl { host, port, params })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn socket_addr(&self) -> (&str, u16) {
        (self.host(), self.port())
    }

    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// `0.0.0.0` means "listen here".
    pub fn is_listener(&self) -> bool {
        self.host == "0.0.0.0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_caller_url() {
        let url = SrtUrl::parse("srt://example.com:9000").unwrap();
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.port(), 9000);
        assert!(url.params().is_empty());
        assert!(!url.is_listener());
    }

    #[test]
    fn parse_listener_urls() {
        assert!(SrtUrl::parse("srt://:9000").unwrap().is_listener());
        assert!(SrtUrl::parse("srt://0.0.0.0:9000").unwrap().is_listener());
        assert!(!SrtUrl::parse("srt://127.0.0.1:9000").unwrap().is_listener());
        assert_eq!(SrtUrl::parse("srt://:9000").unwrap().host(), "0.0.0.0");
    }

    #[test]
    fn parse_query_params() {
        let url = SrtUrl::parse("srt://host:1?latency=200&streamid=#!::r=live&flag").unwrap();
        assert_eq!(url.host(), "host");
        assert_eq!(url.port(), 1);
        assert_eq!(
            url.params(),
            &[
                ("latency".to_string(), "200".to_string()),
                ("streamid".to_string(), "#!::r=live".to_string()),
                ("flag".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn parse_rejects_bad_urls() {
        assert!(SrtUrl::parse("udp://host:1").is_err());
        assert!(SrtUrl::parse("srt://hostonly").is_err());
        assert!(SrtUrl::parse("srt://host:notaport").is_err());
        assert!(SrtUrl::parse("srt://host:99999").is_err());
    }
}
