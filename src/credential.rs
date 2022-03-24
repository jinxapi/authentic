use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::AuthenticationProcess;

pub trait AuthenticationCredential: AuthenticationProcess {}

pub trait AuthenticationCredentialToken {
    fn token(&self) -> &[u8];
}

pub trait AuthenticationCredentialUsernamePassword {
    fn username(&self) -> &str;
    fn password(&self) -> &str;
}

pub struct TokenCredential {
    current_token: Cow<'static, [u8]>,
}

impl TokenCredential {
    pub fn new(token: Cow<'static, [u8]>) -> Arc<Self> {
        Arc::new(Self {
            current_token: token,
        })
    }
}

impl AuthenticationProcess for TokenCredential {}
impl AuthenticationCredential for TokenCredential {}

impl AuthenticationCredentialToken for TokenCredential {
    fn token(&self) -> &[u8] {
        self.current_token.as_ref()
    }
}

pub struct UsernamePasswordCredential {
    current_username: Cow<'static, str>,
    current_password: Cow<'static, str>,
}

impl UsernamePasswordCredential {
    pub fn new(
        username: Cow<'static, str>,
        password: Cow<'static, str>,
    ) -> Arc<UsernamePasswordCredential> {
        Arc::new(UsernamePasswordCredential {
            current_username: username,
            current_password: password,
        })
    }
}

impl AuthenticationProcess for UsernamePasswordCredential {}
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
pub struct HttpRealmCredential<Credential> {
    realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>,
}

impl<Credential> HttpRealmCredential<Credential> {
    pub fn new(
        realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>,
    ) -> Arc<HttpRealmCredential<Credential>> {
        Arc::new(HttpRealmCredential { realm_credentials })
    }

    pub fn get_credential(&self, realm: &str) -> Option<&Arc<Credential>> {
        self.realm_credentials.get(realm)
    }
}

impl<Credential> AuthenticationProcess for HttpRealmCredential<Credential> {}
impl<Credential> AuthenticationCredential for HttpRealmCredential<Credential> {}
