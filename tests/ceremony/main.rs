//! The live ceremony suite, run against this bridge: the rungs of
//! `ceremony-tests`, each under the name CI selects it by, with the bridge as
//! the deployment under test. Built only with `--features live-ceremony`;
//! needs `GH_OAUTH_CLIENT_ID`, `GH_OAUTH_CLIENT_SECRET` (the App's client
//! secret, which the bridge publishes as the public `clientCredential`) and
//! `LIBID_TEST_PUBLIC_ORIGIN`, for the GitHub authorization rung the test
//! account (`GH_TEST_ALICE_*`) and a Chrome, and for the X authorization rung
//! `X_OAUTH_CLIENT_ID`, `LIBID_TEST_X_REDIRECT_URI` and the X test account
//! (`X_TEST_ALICE_*`). A missing variable fails the run.

#[path = "../common/mod.rs"]
// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;
mod host;

use ceremony_tests::rungs;
use host::Host;

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_code_fails_the_token_session_with_githubs_answer() {
    rungs::a_refused_code_fails_the_token_session_with_githubs_answer(
        &Host::attesting().await,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_github_refuses_fails_the_token_session() {
    rungs::a_credential_github_refuses_fails_the_token_session(&Host::attesting().await)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_github_refuses_fails_the_identity_session() {
    rungs::a_bearer_github_refuses_fails_the_identity_session().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_github_authorization_yields_two_sessions_the_notary_attested() {
    rungs::a_real_github_authorization_yields_two_sessions_the_notary_attested(
        &Host::attesting().await,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_x_refuses_fails_the_identity_session() {
    rungs::a_bearer_x_refuses_fails_the_identity_session().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_x_authorization_yields_two_sessions_the_notary_attested() {
    rungs::a_real_x_authorization_yields_two_sessions_the_notary_attested().await
}

/// Run by name, ignored otherwise:
/// `X_COOKIE_EXPORT=x.com.json cargo test --features live-ceremony --test
/// ceremony -- --ignored --nocapture a_browser_export`.
#[tokio::test]
#[ignore]
async fn a_browser_export_becomes_the_x_secret() {
    rungs::a_browser_export_becomes_the_x_secret().await
}

/// Run by name, ignored otherwise:
/// `cargo test --features live-ceremony --test ceremony -- --ignored
/// --nocapture a_fresh_x_session`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_fresh_x_session_is_exported_for_the_secret() {
    rungs::a_fresh_x_session_is_exported_for_the_secret().await
}

/// The Google rung, under the module path CI selects with `--exact`.
mod google {
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires Google client settings and saved session; explicit live run"]
    async fn a_real_google_authorization_returns_a_verified_id_token() {
        ceremony_tests::google::a_real_google_authorization_returns_a_verified_id_token()
            .await
    }
}

/// Two checks of the crate's browser layer, under the module paths the
/// workflow and the README select with `--exact`.
mod browser {
    pub mod google {
        mod tests {
            #[tokio::test(flavor = "multi_thread")]
            #[ignore = "reads a profile a person signed in to; explicit run"]
            async fn a_fresh_google_session_is_exported_for_the_secret() {
                ceremony_tests::browser::google::export_fresh_session().await
            }

            #[tokio::test]
            #[ignore = "requires Chrome and local sockets; no account or external network"]
            async fn chrome_preserves_the_redirect_fragment() {
                ceremony_tests::browser::google::chrome_preserves_the_redirect_fragment()
                    .await
            }
        }
    }
}
