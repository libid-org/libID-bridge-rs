//! A saved session: the cookies of a signed-in browser as an export carries
//! them, as a test setting holds them, and as Chrome takes them back.

use base64::Engine;
use chromiumoxide::cdp::browser_protocol::network::{
    Cookie as Held,
    CookieParam,
    CookieSameSite,
    SetCookiesParams,
};
use serde::{
    Deserialize,
    Serialize,
};

use super::Session;
use crate::env::optional;

/// One cookie of a saved session. `same_site` is absent where the browser
/// reported none; `expires` is `0` for a session cookie.
#[derive(Clone, Serialize, Deserialize)]
pub struct Stored {
    pub name: String,
    pub value: String,
    /// With a leading dot for a domain cookie; the host alone for a host-only
    /// one.
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<CookieSameSite>,
    #[serde(default)]
    pub expires: f64,
}

impl Stored {
    /// The cookie as Chrome holds it.
    pub fn held(c: Held) -> Stored {
        Stored {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            http_only: c.http_only,
            same_site: c.same_site,
            expires: c.expires,
        }
    }

    /// The cookie's host, without the leading dot.
    pub fn host(&self) -> &str {
        self.domain.trim_start_matches('.')
    }

    /// The parameter that sets this cookie: on its domain when it has one,
    /// on its host alone otherwise. A host-only cookie has no Domain
    /// attribute, and a `__Host-` one may not be given one; `url` alone
    /// places it on its host.
    pub fn param(&self) -> CookieParam {
        let mut param = CookieParam::new(self.name.clone(), self.value.clone());
        param.url = Some(format!("https://{}/", self.host()));
        if self.domain.starts_with('.') {
            param.domain = Some(self.domain.clone());
        }
        param.path = Some(if self.path.is_empty() {
            "/".into()
        } else {
            self.path.clone()
        });
        param.secure = Some(self.secure);
        param.http_only = Some(self.http_only);
        param.same_site = self.same_site.clone();
        if self.expires > 0.0 {
            param.expires = Some(
                chromiumoxide::cdp::browser_protocol::network::TimeSinceEpoch::new(
                    self.expires,
                ),
            );
        }
        param
    }
}

/// The cookies of `export` for the hosts `keep` admits: a list, or
/// Playwright's `storageState` carrying one under `cookies`; each field under
/// its camelCase or snake_case name; `sameSite` in any spelling, absent where
/// unspecified. An expired cookie is left out, as Chrome would drop it on
/// arrival.
pub fn parse(
    export: &[u8],
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<Stored>, &'static str> {
    let document: serde_json::Value =
        serde_json::from_slice(export).map_err(|_| "invalid export JSON")?;
    let list = document
        .get("cookies")
        .unwrap_or(&document)
        .as_array()
        .ok_or("expected a cookie list, or one under `cookies`")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default();
    let mut cookies = Vec::new();
    for item in list {
        let field = |names: &[&str]| names.iter().find_map(|n| item.get(*n));
        let text = |names: &[&str]| field(names).and_then(|v| v.as_str());
        let (Some(name), Some(value), Some(domain)) = (
            text(&["name", "Name"]),
            text(&["value", "Value"]),
            text(&["domain", "Domain"]),
        ) else {
            return Err("a cookie names its name, value and domain");
        };
        if !keep(domain.trim_start_matches('.')) {
            continue;
        }
        let expires = field(&["expires", "expirationDate"])
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if expires > 0.0 && expires < now {
            continue;
        }
        let same_site = match text(&["sameSite", "same_site"]).unwrap_or_default() {
            s if s.eq_ignore_ascii_case("strict") => Some(CookieSameSite::Strict),
            s if s.eq_ignore_ascii_case("lax") => Some(CookieSameSite::Lax),
            s if s.eq_ignore_ascii_case("none")
                || s.eq_ignore_ascii_case("no_restriction") =>
            {
                Some(CookieSameSite::None)
            }
            _ => None,
        };
        cookies.push(Stored {
            name: name.to_owned(),
            value: value.to_owned(),
            domain: domain.to_owned(),
            path: text(&["path", "Path"]).unwrap_or("/").to_owned(),
            secure: field(&["secure", "Secure"])
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            http_only: field(&["httpOnly", "http_only"])
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            same_site,
            expires,
        });
    }
    Ok(cookies)
}

/// The saved session `prefix` names, for the hosts `keep` admits:
/// `{prefix}_COOKIES`, the base64 an export prints, or else
/// `{prefix}_COOKIES_FILE`, the JSON it writes; `None` where neither is set.
pub fn from_env(prefix: &str, keep: impl Fn(&str) -> bool) -> Option<Vec<Stored>> {
    let export = if let Some(encoded) = optional(&format!("{prefix}_COOKIES")) {
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .unwrap_or_else(|e| panic!("{prefix}_COOKIES is base64: {e}"))
    } else {
        let path = optional(&format!("{prefix}_COOKIES_FILE"))?;
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{prefix}_COOKIES_FILE, {path}: {e}"))
    };
    Some(parse(&export, keep).unwrap_or_else(|e| panic!("{prefix}_COOKIES: {e}")))
}

/// Set `cookies` in `session`, on the blank page. Chrome refuses a cookie it
/// cannot place and says nothing; the profile is fresh, so what it holds
/// afterwards is exactly what it accepted.
pub async fn restore(session: &Session, cookies: impl IntoIterator<Item = CookieParam>) {
    let params: Vec<CookieParam> = cookies.into_iter().collect();
    // Chrome refuses an empty list.
    if params.is_empty() {
        return;
    }
    session
        .page
        .execute(SetCookiesParams::new(params))
        .await
        .expect("Chrome takes the saved session's cookies");
}

/// The value the `_COOKIES` setting takes: base64 of the JSON list.
pub fn encoded(cookies: &[Stored]) -> String {
    base64::engine::general_purpose::STANDARD.encode(json(cookies))
}

fn json(cookies: &[Stored]) -> Vec<u8> {
    serde_json::to_vec(cookies).expect("a cookie list serializes")
}

/// Deliver an export: as JSON at the path `out_var` names, whole or not at
/// all, so a failed export never empties the file a rung reads and the value
/// never crosses a terminal; or printed as the `{secret}=` value otherwise.
pub fn deliver(cookies: &[Stored], out_var: &str, secret: &str) {
    match optional(out_var) {
        Some(path) => {
            let staged = format!("{path}.tmp");
            write_private(&staged, &json(cookies));
            std::fs::rename(&staged, &path).expect("place the export");
            println!("wrote {} cookies to {path}", cookies.len());
        }
        None => println!("{secret}={}", encoded(cookies)),
    }
}

/// `bytes` into a new file at `path` that its owner alone may read: the
/// export is a live session. A file left there by an earlier run is replaced.
fn write_private(path: &str, bytes: &[u8]) {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .expect("write the export");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn an_export_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        let path = path.to_str().unwrap();
        std::fs::write(path, b"left by an earlier run").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(path, b"[]");
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(path).unwrap(), b"[]");
    }

    fn google(host: &str) -> bool {
        host == "google.com" || host.ends_with(".google.com")
    }

    #[test]
    fn only_the_hosts_the_caller_admits() {
        let list = parse(
            br#"[{"name":"SID","value":"fake","domain":"evilgoogle.com"},
                 {"name":"SID","value":"fake","domain":".google.com"}]"#,
            google,
        )
        .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].domain, ".google.com");
    }

    #[test]
    fn a_storage_state_carries_its_list_under_cookies() {
        let list = parse(
            br#"{"cookies":[{"name":"auth_token","value":"fake","domain":".x.com",
                              "sameSite":"no_restriction","expirationDate":4102444800}]}"#,
            |h| h.ends_with("x.com"),
        )
        .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].same_site, Some(CookieSameSite::None));
        assert_eq!(list[0].expires, 4102444800.0);
    }

    #[test]
    fn an_expired_cookie_is_left_out() {
        let list = parse(
            br#"[{"name":"old","value":"fake","domain":".x.com","expires":1},
                 {"name":"session","value":"fake","domain":".x.com"}]"#,
            |_| true,
        )
        .unwrap();
        assert_eq!(
            list.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            ["session"]
        );
    }

    #[test]
    fn a_host_only_cookie_carries_no_domain_attribute() {
        let list = parse(
            br#"[{"name":"__Host-GAPS","value":"fake","domain":"accounts.google.com"},
                 {"name":"SID","value":"fake","domain":".google.com"}]"#,
            google,
        )
        .unwrap();
        let param = |n: &str| list.iter().find(|c| c.name == n).unwrap().param();
        assert_eq!(param("__Host-GAPS").domain, None);
        assert_eq!(
            param("__Host-GAPS").url.as_deref(),
            Some("https://accounts.google.com/")
        );
        assert_eq!(param("SID").domain.as_deref(), Some(".google.com"));
    }

    #[test]
    fn what_an_export_prints_parses_back() {
        let stored = vec![Stored {
            name: "auth_token".into(),
            value: "fake".into(),
            domain: ".x.com".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            same_site: Some(CookieSameSite::Lax),
            expires: 0.0,
        }];
        let json = json(&stored);
        let back = parse(&json, |_| true).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].same_site, Some(CookieSameSite::Lax));
        assert!(back[0].http_only);
    }
}
