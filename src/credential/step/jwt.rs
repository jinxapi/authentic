use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use crate::credential::{AuthenticationCredential, FetchedToken};
use crate::AuthenticError;

/// An implementation of [`FetchedToken`] returned from [`JsonWebTokenCredential`].
pub struct FetchedJsonWebTokenCredential {
    token: Vec<u8>,
    renew: std::time::SystemTime,
    expiry: std::time::SystemTime,
}

/// Credential wrapping a JWT (JSON Web Token).
///
/// From a private secret or private key, this will create short-lived tokens in JWT format.
/// The credential can be used indefintely, but the underlying token will be rotated before it
/// expires.
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

impl JsonWebTokenCredential {
    /// Create a JWT credential with specific properties.
    ///
    /// The `header` and `key` parameters are set as for [`jsonwebtoken`].
    ///
    /// The `expiration` parameter controls how long the token will be valid. Endpoints may restrict
    /// tokens to a maximum lifetime. Tokens are rotated after half the expiration time, to ensure
    /// that they have a reasonable remaining time to be used.
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
