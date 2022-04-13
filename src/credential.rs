use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::AuthenticError;

pub trait AuthenticationCredential {
    type Fetch;

    fn auth_step(&self) -> Result<Duration, AuthenticError> {
        Ok(Duration::ZERO)
    }

    fn fetch(&self) -> Result<Self::Fetch, AuthenticError>;
}

pub trait FetchedToken {
    fn token(&self) -> &[u8];
}

pub trait FetchedUsernamePassword {
    fn username(&self) -> &str;
    fn password(&self) -> &str;
}

pub struct FetchedTokenCredential {
    token: Cow<'static, [u8]>,
}

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

pub struct FetchedUsernamePasswordCredential {
    username: Cow<'static, str>,
    password: Cow<'static, str>,
}

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

/// Credential mapping realms to username/password credentials.
///
/// For HTTP authentication, this selects the correct username/password credential for the realm
/// returned by the `www-authenticate` header.
pub struct FetchedHttpRealmCredentials<Credential> {
    realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>,
}

pub struct HttpRealmCredentials<Credential> {
    current: Arc<FetchedHttpRealmCredentials<Credential>>,
}

impl<Credential> HttpRealmCredentials<Credential> {
    pub fn new(realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>) -> Self {
        Self {
            current: Arc::new(FetchedHttpRealmCredentials { realm_credentials }),
        }
    }
}

impl<Credential> AuthenticationCredential for HttpRealmCredentials<Credential> {
    type Fetch = Arc<FetchedHttpRealmCredentials<Credential>>;

    fn fetch(&self) -> Result<Self::Fetch, AuthenticError> {
        Ok(self.current.clone())
    }
}

impl<Credential> FetchedHttpRealmCredentials<Credential> {
    pub fn credential(&self, realm: &str) -> Option<&Arc<Credential>> {
        self.realm_credentials.get(realm)
    }
}
