use std::borrow::Cow;
use std::sync::Arc;

use crate::AuthenticError;

use super::{AuthenticationCredential, FetchedToken, FetchedUsernamePassword};

/// An implementation of [`FetchedToken`] returned from [`TokenCredential`].
pub struct FetchedTokenCredential {
    token: Cow<'static, [u8]>,
}

/// Credential wrapping a token to be used as an API key header or for Bearer authentication.
pub struct TokenCredential {
    current: Arc<FetchedTokenCredential>,
}

impl TokenCredential {
    pub fn new(token: impl Into<Cow<'static, [u8]>>) -> Self {
        Self {
            current: Arc::new(FetchedTokenCredential {
                token: token.into(),
            }),
        }
    }
}

impl AuthenticationCredential for TokenCredential {
    type Fetch = Arc<FetchedTokenCredential>;

    fn fetch(&self) -> Result<Self::Fetch, AuthenticError> {
        Ok(self.current.clone())
    }
}

impl FetchedToken for Arc<FetchedTokenCredential> {
    fn token(&self) -> &[u8] {
        self.token.as_ref()
    }
}

/// An implementation of [`FetchedUsernamePassword`] returned from [`UsernamePasswordCredential`].
pub struct FetchedUsernamePasswordCredential {
    username: Cow<'static, str>,
    password: Cow<'static, str>,
}

/// Credential wrapping a username and password.
pub struct UsernamePasswordCredential {
    current: Arc<FetchedUsernamePasswordCredential>,
}

impl UsernamePasswordCredential {
    pub fn new(
        username: impl Into<Cow<'static, str>>,
        password: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            current: Arc::new(FetchedUsernamePasswordCredential {
                username: username.into(),
                password: password.into(),
            }),
        }
    }
}

impl AuthenticationCredential for UsernamePasswordCredential {
    type Fetch = Arc<FetchedUsernamePasswordCredential>;

    fn fetch(&self) -> Result<Self::Fetch, AuthenticError> {
        Ok(self.current.clone())
    }
}

impl FetchedUsernamePassword for Arc<FetchedUsernamePasswordCredential> {
    fn username(&self) -> &str {
        self.username.as_ref()
    }
    fn password(&self) -> &str {
        self.password.as_ref()
    }
}
