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

#[cfg(feature = "jwt")]
pub struct FetchedJsonWebTokenCredential {
    token: Vec<u8>,
    renew: std::time::SystemTime,
    expiry: std::time::SystemTime,
}

#[cfg(feature = "jwt")]
pub struct JsonWebTokenCredential {
    current: arc_swap::ArcSwapOption<FetchedJsonWebTokenCredential>,
    // Mutex to be held while renewing. Contains a copy of the renew time
    // to prevent race conditions.
    renewing: std::sync::Mutex<std::time::SystemTime>,
    header: jsonwebtoken::Header,
    key: jsonwebtoken::EncodingKey,
    expiration: Duration,
    jwt_iss: Option<Cow<'static, str>>,
}

#[cfg(feature = "jwt")]
impl JsonWebTokenCredential {
    pub fn new(
        header: jsonwebtoken::Header,
        key: jsonwebtoken::EncodingKey,
        expiration: Duration,
    ) -> Self {
        Self {
            current: arc_swap::ArcSwapOption::from(None),
            renewing: std::sync::Mutex::new(std::time::SystemTime::UNIX_EPOCH),
            header,
            key,
            expiration,
            jwt_iss: None,
        }
    }

    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<Cow<'static, str>>) -> Self {
        self.jwt_iss = Some(issuer.into());
        self
    }
}

#[cfg(feature = "jwt")]
#[derive(Debug, serde::Serialize)]
struct JWTClaims {
    iat: usize,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    iss: Option<Cow<'static, str>>,
}

#[cfg(feature = "jwt")]
impl AuthenticationCredential for JsonWebTokenCredential {
    fn auth_step(&self) -> Result<Duration, AuthenticError> {
        let now = std::time::SystemTime::now();
        let current_is_valid = {
            let guard = self.current.load();
            if let Some(current) = &*guard {
                if now < current.renew {
                    // Current token is valid and too early to renew.
                    return Ok(Duration::ZERO);
                } else {
                    now < current.expiry
                }
            } else {
                false
            }
        };
        match self.renewing.try_lock() {
            // First caller after renewal time locks the mutex and refreshes the token.
            // Other callers fail to lock and continue with the current token if it is still valid,
            // or wait a short time and retry until the lock holder has renewed the token.
            Ok(mut renew_time) => {
                if now < *renew_time {
                    // Caller saw an old token while a previous thread was renewing the token, and
                    // acquired the mutex after the previous thread released it. Prevent the caller
                    // from needlessly renewing the token by checking the renew time again.
                    return Ok(Duration::ZERO);
                }
                let exp = now + self.expiration;
                let claims = JWTClaims {
                    iat: now
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                        .as_secs() as usize,
                    exp: exp
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                        .as_secs() as usize,
                    iss: self.jwt_iss.clone(),
                };
                let token = jsonwebtoken::encode(&self.header, &claims, &self.key)?;
                let renew = now + self.expiration / 2;
                let fetched = FetchedJsonWebTokenCredential {
                    token: token.into_bytes(),
                    renew,
                    expiry: exp,
                };
                self.current.store(Some(Arc::new(fetched)));
                *renew_time = renew;
                Ok(Duration::ZERO)
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if current_is_valid {
                    // Current token is still valid.
                    Ok(Duration::ZERO)
                } else {
                    // Current token has expired. Wait for lock holder to refresh token
                    Ok(Duration::from_millis(10))
                }
            }
            Err(std::sync::TryLockError::Poisoned(poison)) => {
                Err(AuthenticError::Other(poison.to_string()))
            }
        }
    }

    type Fetch = Arc<FetchedJsonWebTokenCredential>;

    fn fetch(&self) -> Result<Self::Fetch, AuthenticError> {
        self.current
            .load_full()
            .ok_or_else(|| AuthenticError::Other("Unexpected None".to_owned()))
    }
}

#[cfg(feature = "jwt")]
impl FetchedToken for Arc<FetchedJsonWebTokenCredential> {
    fn token(&self) -> &[u8] {
        &self.token
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
