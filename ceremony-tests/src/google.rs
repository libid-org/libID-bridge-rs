//! Google v1 evidence acquisition and local verification, per
//! libid/specs/platform-ceremonies.md at d946ef8. No proof or chain submission.

use super::{
    browser::{
        google::Authorization,
        Platform,
        Session,
    },
    env,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use http_body_util::BodyExt;
use ring::{
    rand::{
        SecureRandom,
        SystemRandom,
    },
    signature,
};
use serde::Deserialize;

const LIMIT: usize = 32768;

/// One fresh test authorization for a fixed local-chain operation. This is
/// acquisition coverage, not a production claim or a trusted-modulus check.
fn binding() -> (String, String) {
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .expect("OS randomness");
    let state = URL_SAFE_NO_PAD.encode(random);
    let mut chain = [0u8; 32];
    chain[24..].copy_from_slice(&31337u64.to_be_bytes());
    let mut transaction = [0u8; 32];
    transaction[30..].copy_from_slice(&[0xbe, 0xef]);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&libid_crypto::keccak256(b"libid.claim-identity"));
    preimage.extend_from_slice(&1u16.to_be_bytes());
    preimage.extend_from_slice(&libid_crypto::keccak256(&chain));
    preimage.extend_from_slice(&random);
    preimage.extend_from_slice(&32u32.to_be_bytes());
    preimage.extend_from_slice(&transaction);
    (
        state,
        URL_SAFE_NO_PAD.encode(libid_crypto::keccak256(&preimage)),
    )
}

/// Consume one redirect; no bearer or redirect URL appears in diagnostics.
fn token_from_redirect(
    url: &str,
    redirect_uri: &str,
    state: &str,
) -> Result<String, &'static str> {
    if url.len() > LIMIT {
        return Err("redirect exceeds bound");
    }
    let mut parsed = url::Url::parse(url).map_err(|_| "invalid redirect")?;
    let fragment = parsed.fragment().ok_or("missing fragment")?.to_owned();
    parsed.set_fragment(None);
    let expected = url::Url::parse(redirect_uri).map_err(|_| "invalid redirect URI")?;
    if parsed != expected {
        return Err("redirect URI mismatch");
    }
    let mut seen = std::collections::HashSet::new();
    let mut got_state = None;
    let mut token = None;
    let mut error = false;
    // Reject malformed percent encodings before the permissive form decoder.
    for (i, b) in fragment.bytes().enumerate() {
        if b == b'%'
            && !fragment
                .as_bytes()
                .get(i + 1..i + 3)
                .is_some_and(|v| v.iter().all(u8::is_ascii_hexdigit))
        {
            return Err("malformed fragment encoding");
        }
    }
    for (key, value) in url::form_urlencoded::parse(fragment.as_bytes()) {
        if !seen.insert(key.to_string()) {
            return Err("duplicate fragment field");
        }
        if value.contains('\u{fffd}') {
            return Err("invalid fragment UTF-8");
        }
        match key.as_ref() {
            "state" => got_state = Some(value.into_owned()),
            "id_token" => token = Some(value.into_owned()),
            // The issuer identifies itself on the response (RFC 9207); a
            // response another server composed is refused here, before its
            // token is opened.
            "iss" => {
                if value != "https://accounts.google.com" {
                    return Err("redirect issuer mismatch");
                }
            }
            "error" => error = true,
            // Google's own annotations on an `id_token` response; none carries
            // a credential, so none is read.
            "error_description" | "error_uri" | "authuser" | "prompt"
            | "version_info" => {}
            other => {
                eprintln!("Google redirect carries a fragment field this rung does not admit: {other}");
                return Err("unexpected fragment field");
            }
        }
    }
    if got_state.as_deref() != Some(state) {
        return Err("state mismatch");
    }
    if error {
        return Err("Google returned an authorization error");
    }
    token.filter(|s| !s.is_empty()).ok_or("missing ID token")
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    nonce: String,
    email: String,
    email_verified: bool,
    exp: u64,
}
#[derive(Deserialize)]
struct Keys {
    keys: Vec<Key>,
}
#[derive(Deserialize)]
struct Key {
    kty: String,
    kid: String,
    alg: String,
    n: String,
    e: String,
}

fn verify(
    token: &str,
    jwks: &[u8],
    client: &str,
    nonce: &str,
    email: &str,
    now: u64,
) -> Result<(), &'static str> {
    if token.len() > LIMIT {
        return Err("ID token exceeds bound");
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT framing");
    }
    let decode = |s| {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| "invalid JWT encoding")
    };
    let header: Header =
        serde_json::from_slice(&decode(parts[0])?).map_err(|_| "invalid JWT header")?;
    if header.alg != "RS256" {
        return Err("unexpected signature algorithm");
    }
    let keys: Keys = serde_json::from_slice(jwks).map_err(|_| "invalid Google JWKS")?;
    let matches: Vec<_> = keys.keys.iter().filter(|k| k.kid == header.kid).collect();
    if matches.len() != 1 {
        return Err("signing key unavailable or ambiguous");
    }
    let key = matches[0];
    if key.kty != "RSA" || key.alg != "RS256" {
        return Err("unexpected key type");
    }
    let n = decode(&key.n)?;
    let e = decode(&key.e)?;
    if e != [1, 0, 1] {
        return Err("Google profile requires exponent 65537");
    }
    let signed = format!("{}.{}", parts[0], parts[1]);
    signature::RsaPublicKeyComponents { n: &n, e: &e }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signed.as_bytes(),
            &decode(parts[2])?,
        )
        .map_err(|_| "invalid ID-token signature")?;
    let claims: Claims = serde_json::from_slice(&decode(parts[1])?)
        .map_err(|_| "invalid signed claims")?;
    if claims.iss != "https://accounts.google.com" {
        return Err("issuer mismatch");
    }
    if claims.aud != client {
        return Err("audience mismatch");
    }
    if claims.nonce != nonce || decode(&claims.nonce)?.len() != 32 {
        return Err("nonce mismatch");
    }
    if claims.exp <= now {
        return Err("expired ID token");
    }
    if !claims.email_verified || !claims.email.eq_ignore_ascii_case(email) {
        return Err("verified account mismatch");
    }
    if claims.sub.is_empty()
        || claims.sub.len() > 255
        || !claims.sub.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err("invalid Google subject");
    }
    Ok(())
}

/// Fetch only the fixed Google JWKS endpoint over verified TLS, with a bound
/// and a deadline. The signed token is never sent to a validation service.
async fn jwks() -> Vec<u8> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    let client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build::<_, http_body_util::Empty<bytes::Bytes>>(https);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let response = client
            .get(
                "https://www.googleapis.com/oauth2/v3/certs"
                    .parse()
                    .expect("the JWKS URL"),
            )
            .await
            .expect("Google JWKS response");
        assert_eq!(response.status(), 200, "Google JWKS status");
        http_body_util::Limited::new(response.into_body(), 128 * 1024)
            .collect()
            .await
            .expect("bounded JWKS body")
            .to_bytes()
            .to_vec()
    })
    .await
    .expect("Google JWKS deadline")
}

/// A real Google authorization from the saved session, and the ID token it
/// returns verified against Google's keys: signature, state, nonce,
/// audience, expiry, subject and the verified account.
pub async fn a_real_google_authorization_returns_a_verified_id_token() {
    env::logging();
    let (state, nonce) = binding();
    let authorization = Authorization::from_env(state, nonce);
    // Resolve keys before asking the browser for evidence.
    let keys = jwks().await;
    let mut session = Session::open(&authorization).await;
    let landed = authorization.authorize(&mut session).await;
    let _ = session.close().await;
    let token =
        token_from_redirect(&landed, &authorization.redirect_uri, &authorization.state)
            .expect("valid Google response");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify(
        &token,
        &keys,
        &authorization.client_id,
        &authorization.nonce,
        &authorization.email,
        now,
    )
    .expect("Google signature and ceremony claims");
    eprintln!("Google ID token: signature, state, nonce, audience, expiry, subject and verified account passed");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fetch reaches Google over verified TLS and returns a key set the
    /// verifier reads: RSA keys, each with an id.
    #[tokio::test]
    #[ignore = "reaches www.googleapis.com"]
    async fn the_jwks_is_googles_rsa_key_set() {
        let keys: Keys = serde_json::from_slice(&jwks().await).expect("a JWKS");
        assert!(!keys.keys.is_empty());
        assert!(keys
            .keys
            .iter()
            .all(|k| k.kty == "RSA" && !k.kid.is_empty()));
    }

    #[test]
    fn fragment_rejects_confused_or_malformed_responses() {
        let base = "https://bridge.example/auth/callback";
        assert_eq!(
            token_from_redirect(&format!("{base}#state=s&id_token=token"), base, "s"),
            Ok("token".into())
        );
        assert_eq!(
            token_from_redirect(
                &format!("{base}#state=s&id_token=token&authuser=0&prompt=consent&version_info=CmMK&iss=https%3A%2F%2Faccounts.google.com"),
                base,
                "s"
            ),
            Ok("token".into()),
            "Google's annotations on the response are ignored, not refused"
        );
        for fragment in [
            "state=wrong&id_token=token",
            "state=s&state=s&id_token=token",
            "state=s&id_token=token&code=x",
            "state=s&id_token=token&iss=https%3A%2F%2Faccounts.example",
            "state=s&id_token=token&access_token=x",
            "state=s&id_token=token&error=denied",
            "state=s&id_token=%ZZ",
            "state=s&id_token=%FF",
            "state=s&id_token=",
            "state=s&error=denied",
        ] {
            assert!(
                token_from_redirect(&format!("{base}#{fragment}"), base, "s").is_err()
            );
        }
        assert!(token_from_redirect(
            "https://bridge.example/auth/callback/extra#state=s&id_token=t",
            base,
            "s"
        )
        .is_err());
    }

    #[test]
    fn the_redirect_uri_is_compared_as_a_url() {
        let redirect = "https://bridge.example/auth/callback#state=s&id_token=token";
        for registered in [
            "https://Bridge.example/auth/callback",
            "https://bridge.example:443/auth/callback",
        ] {
            assert_eq!(
                token_from_redirect(redirect, registered, "s"),
                Ok("token".into()),
                "{registered}"
            );
        }
        assert_eq!(
            token_from_redirect(
                redirect,
                "https://bridge.example:8443/auth/callback",
                "s"
            ),
            Err("redirect URI mismatch")
        );
    }

    #[test]
    fn authentic_signature_and_claim_bindings_are_required() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/google-jwt.json")).unwrap();
        let token = fixture["token"].as_str().unwrap();
        let keys = serde_json::to_vec(&fixture["jwks"]).unwrap();
        let nonce = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert!(verify(
            token,
            &keys,
            "test-client",
            &nonce,
            "alice@example.com",
            1000
        )
        .is_ok());
        for (client, nonce, email, now) in [
            ("wrong", nonce.as_str(), "alice@example.com", 1000),
            ("test-client", "wrong", "alice@example.com", 1000),
            ("test-client", nonce.as_str(), "other@example.com", 1000),
            ("test-client", nonce.as_str(), "alice@example.com", 2000),
        ] {
            assert!(verify(token, &keys, client, nonce, email, now).is_err());
        }
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
        payload["email"] = "attacker@example.com".into();
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        assert_eq!(
            verify(
                &parts.join("."),
                &keys,
                "test-client",
                &nonce,
                "attacker@example.com",
                1000
            ),
            Err("invalid ID-token signature")
        );
    }
}
