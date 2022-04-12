use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::AuthenticError;

pub trait AuthenticationCredential {
    fn auth_step(&mut self) -> Duration {
        Duration::ZERO
    }
}

pub trait AuthenticationCredentialToken: AuthenticationCredential {
    fn token(&self) -> Result<Arc<Vec<u8>>, AuthenticError>;
}

pub trait AuthenticationCredentialUsernamePassword: AuthenticationCredential {
    fn username(&self) -> &str;
    fn password(&self) -> &str;
}

pub struct TokenCredential {
    current_token: Arc<Vec<u8>>,
}

impl TokenCredential {
    pub fn new(token: impl Into<Cow<'static, [u8]>>) -> Arc<Self> {
        Arc::new(Self {
            current_token: Arc::new(token.into().into_owned()),
        })
    }
}

impl AuthenticationCredential for TokenCredential {}

impl AuthenticationCredentialToken for TokenCredential {
    fn token(&self) -> Result<Arc<Vec<u8>>, AuthenticError> {
        Ok(self.current_token.clone())
    }
}

pub struct UsernamePasswordCredential {
    current_username: Cow<'static, str>,
    current_password: Cow<'static, str>,
}

impl UsernamePasswordCredential {
    pub fn new(
        username: impl Into<Cow<'static, str>>,
        password: impl Into<Cow<'static, str>>,
    ) -> Arc<UsernamePasswordCredential> {
        Arc::new(UsernamePasswordCredential {
            current_username: username.into(),
            current_password: password.into(),
        })
    }
}

impl AuthenticationCredential for UsernamePasswordCredential {}

impl AuthenticationCredentialUsernamePassword for UsernamePasswordCredential {
    fn username(&self) -> &str {
        self.current_username.as_ref()
    }
    fn password(&self) -> &str {
        self.current_password.as_ref()
    }
}

/// Credential mapping realms to username/password credentials.
///
/// For HTTP authentication, this selects the correct username/password credential for the realm
/// returned by the `www-authenticate` header.
pub struct HttpRealmCredentials<Credential> {
    realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>,
}

impl<Credential> HttpRealmCredentials<Credential> {
    pub fn new(
        realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>,
    ) -> Arc<HttpRealmCredentials<Credential>> {
        Arc::new(HttpRealmCredentials { realm_credentials })
    }

    pub fn get_credential(&self, realm: &str) -> Option<&Arc<Credential>> {
        self.realm_credentials.get(realm)
    }
}

impl<Credential> AuthenticationCredential for HttpRealmCredentials<Credential> {}
