//! The checks that need no deployment: a Chrome, and the X and Google exports.

#[tokio::test]
#[ignore]
async fn a_browser_export_becomes_the_x_secret() {
    ceremony_tests::rungs::a_browser_export_becomes_the_x_secret().await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_fresh_x_session_is_exported_for_the_secret() {
    ceremony_tests::rungs::a_fresh_x_session_is_exported_for_the_secret().await
}

/// Paths the workflow and the README select with `--exact`.
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
