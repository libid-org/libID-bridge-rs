//! The OAuth application this service authenticates as.

use secrecy::SecretString;

/// The confidential client registered with GitHub.
#[derive(Clone, Debug)]
pub struct OAuthCredentials {
    /// The client identifier. Public: the browser sends it in the
    /// authorization request, and the token request reveals it.
    pub client_id: String,
    /// The client secret. It never leaves this process and is committed, not
    /// revealed, in the notarized transcript; it is read where the request
    /// body is written and nowhere else. The body is form-encoded, so `&`
    /// and `=` in the value are percent-encoded.
    pub client_secret: SecretString,
}
