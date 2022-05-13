use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::AuthenticError;

use super::AuthenticationCredential;

pub struct FetchedHttpRealmCredentials<Credential> {
    realm_credentials: HashMap<Cow<'static, str>, Arc<Credential>>,
}

/// Map of realms to another type of credential.
///
/// For HTTP authentication, this selects the correct credential for the realm
/// returned by the `www-authenticate` header.
pub struct HttpRealmCredentials<Credential> {
    current: Arc<FetchedHttpRealmCredentials<Credential>>,
}

impl<Credential> HttpRealmCredentials<Credential> {
    /// Create a set of credentials mapped to HTTP realms.
    ///
    /// When a `www-authenticate` header is returned from a HTTP request, the realm will
    /// be used to select the appropriate credentials for a subsequent request.
    ///
    /// Takes a HashMap mapping realm names to another credential type. For example, for HTTP Basic
    /// authentication each realm maps to a [`super::UsernamePasswordCredential`].
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
    /// Get the correct credential for a specified realm.
    ///
    /// Returns `None` if no credential has been specified for the realm.
    pub fn credential(&self, realm: &str) -> Option<&Arc<Credential>> {
        self.realm_credentials.get(realm)
    }
}
