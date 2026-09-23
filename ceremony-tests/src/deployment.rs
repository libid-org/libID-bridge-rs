//! The deployment under test, as the GitHub rungs see it.

/// The github entry the deployment publishes: what a ceremony starts from.
pub struct Published {
    pub client_id: String,
    pub credential: String,
}

/// Where the OAuth App redirects to, and what the deployment publishes for a
/// ceremony to start from. The X and Google rungs take no deployment.
// A rung awaits this in its own task and never sends it across one.
#[allow(async_fn_in_trait)]
pub trait Deployment {
    /// The callback URL the OAuth App registers: the public origin followed
    /// by the callback path.
    fn redirect_uri(&self) -> String;

    /// The github entry as the deployment publishes it now, read the way an
    /// application reads it.
    async fn published(&self) -> Published;
}
