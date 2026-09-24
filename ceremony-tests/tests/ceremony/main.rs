//! The live ceremony suite: the rungs of `ceremony-tests`, each under the
//! name CI selects it by, with this repository's bridge as the deployment
//! under test, and the exports and Chrome checks that need no deployment. Run
//! from `ceremony-tests/`, where relative paths in its settings resolve. Each
//! test loads the settings sections its rung reads, and a missing variable
//! fails it, naming every one absent; `ceremony_tests::settings::VARIABLES`
//! lists them all.

mod host;
mod settings_sync;

use ceremony_tests::{
    rungs::{
        self,
        Published,
    },
    settings::{
        self,
        both,
        GitHubApp,
    },
};
use host::Host;

/// What the bridge under test publishes, configured with `app`. The bridge
/// stops when the host drops; the rungs read only what it published.
async fn published(app: &GitHubApp) -> Published {
    Host::attesting(app).await.published(app).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_code_fails_the_token_session_with_githubs_answer() {
    let published = published(&settings::load(settings::github_app)).await;
    rungs::a_refused_code_fails_the_token_session_with_githubs_answer(&published).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_github_refuses_fails_the_token_session() {
    let published = published(&settings::load(settings::github_app)).await;
    rungs::a_credential_github_refuses_fails_the_token_session(&published).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_github_refuses_fails_the_identity_session() {
    rungs::a_bearer_github_refuses_fails_the_identity_session().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_github_authorization_yields_two_sessions_the_notary_attested() {
    let (app, account) = settings::load(|get| {
        both(settings::github_app(get), settings::github_account(get))
    });
    let published = published(&app).await;
    rungs::a_real_github_authorization_yields_two_sessions_the_notary_attested(
        &published, &account,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_x_refuses_fails_the_identity_session() {
    rungs::a_bearer_x_refuses_fails_the_identity_session().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_x_authorization_yields_two_sessions_the_notary_attested() {
    let ((app, account), session) = settings::load(|get| {
        both(
            both(settings::x_app(get), settings::x_account(get)),
            settings::x_session(get),
        )
    });
    rungs::a_real_x_authorization_yields_two_sessions_the_notary_attested(
        &app, &account, &session,
    )
    .await
}

/// Run by name, ignored otherwise; the crate's README gives the command.
#[tokio::test]
#[ignore]
async fn a_browser_export_becomes_the_x_secret() {
    let export = settings::load(settings::x_conversion);
    rungs::a_browser_export_becomes_the_x_secret(&export)
}

/// Run by name, ignored otherwise; the crate's README gives the command.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_fresh_x_session_is_exported_for_the_secret() {
    let tooling = settings::tooling();
    rungs::a_fresh_x_session_is_exported_for_the_secret(
        tooling.x_profile.clone(),
        tooling.x_export_out.as_deref(),
    )
    .await
}

/// The Google rung, under the module path CI selects with `--exact`.
mod google {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires Google client settings and saved session; explicit live run"]
    async fn a_real_google_authorization_returns_a_verified_id_token() {
        let ((app, account), session) = settings::load(|get| {
            both(
                both(settings::google_app(get), settings::google_account(get)),
                settings::google_session(get),
            )
        });
        ceremony_tests::google::a_real_google_authorization_returns_a_verified_id_token(
            &app, &account, &session,
        )
        .await
    }
}

/// The checks of the crate's browser layer, under the module paths the
/// workflow and the README select with `--exact`.
mod browser {
    pub mod person {
        #[tokio::test(flavor = "multi_thread")]
        #[ignore = "requires Chrome and local sockets; no account or external network"]
        async fn chrome_tells_one_story() {
            ceremony_tests::browser::person::chrome_tells_one_story().await
        }
    }

    pub mod google {
        mod tests {
            #[tokio::test(flavor = "multi_thread")]
            #[ignore = "reads a profile a person signed in to; explicit run"]
            async fn a_fresh_google_session_is_exported_for_the_secret() {
                use ceremony_tests::settings::{
                    self,
                    both,
                };
                let (app, account) = settings::load(|get| {
                    both(settings::google_app(get), settings::google_account(get))
                });
                let tooling = settings::tooling();
                ceremony_tests::browser::google::export_fresh_session(
                    &app,
                    &account,
                    tooling.google_profile.clone(),
                    tooling.google_export_out.as_deref(),
                )
                .await
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
