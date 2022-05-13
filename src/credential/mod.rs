use std::time::Duration;

use crate::AuthenticError;

#[cfg(feature = "loop")]
mod loops;
mod simple;
#[cfg(feature = "step")]
mod step;

#[cfg(feature = "loop")]
pub use loops::*;
pub use simple::*;
#[cfg(feature = "step")]
pub use step::*;

pub trait AuthenticationCredential {
    type Fetch;

    /// Called to perform any processing required for a credential.
    ///
    /// Returns `Ok(Duration::ZERO)` if no further processing is required.  Returns a non-zero
    /// duration if the caller should wait for the duration and call this method again.
    fn auth_step(&self) -> Result<Duration, AuthenticError> {
        Ok(Duration::ZERO)
    }

    /// Get an object containing the credentials to use for an operation.
    ///
    /// Some credentials get rotated over time, so each call may use different credentials.
    /// Calling `fetch` returns an object with a consistent set of credentials to use for a
    /// single operation.
    ///
    /// The returned object typically owns the credentials, or an `Arc` pointing to them. This
    /// ensures that the current credentials live for the duration of the operation, without being
    /// affected by renewals.
    fn fetch(&self) -> Result<Self::Fetch, AuthenticError>;
}

pub trait FetchedToken {
    fn token(&self) -> &[u8];
}

pub trait FetchedUsernamePassword {
    fn username(&self) -> &str;
    fn password(&self) -> &str;
}
