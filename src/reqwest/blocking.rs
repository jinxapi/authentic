//! Authentication schemes for use with blocking `reqwest`.
//! Use the `reqwest_blocking` feature to enable these.

use std::borrow::Cow;
use std::sync::Arc;

use crate::credential::{AuthenticationCredentialToken, AuthenticationCredentialUsernamePassword, HttpRealmCredentials};
use crate::{AuthenticationScheme, AuthenticError};

/// No authentication scheme
///
/// Identical to not using `authentic` but allows minimal code changes when changing schemes.
pub struct NoAuthentication;

impl NoAuthentication {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

impl AuthenticationScheme for NoAuthentication {
    type Builder = reqwest::blocking::RequestBuilder;
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;
}

/// Authentication using a token in a specified haeader.
pub struct HeaderAuthentication<Credential> {
    header_name: Cow<'static, [u8]>,
    credential: Arc<Credential>,
}

impl<Credential: 'static> HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    pub fn new(header_name: Cow<'static, [u8]>, credential: &Arc<Credential>) -> Self {
        Self {
            header_name,
            credential: credential.clone(),
        }
    }
}

impl<Credential> AuthenticationScheme for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    type Builder = reqwest::blocking::RequestBuilder;
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        builder.header(self.header_name.as_ref(), self.credential.token())
    }
}

/// Authentication using HTTP Basic authentication on the initial call without waiting for a challenge.
pub struct BasicAuthentication<Credential> {
    credential: Arc<Credential>,
}

impl<Credential> BasicAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
    pub fn new(credential: &Arc<Credential>) -> Self {
        Self {
            credential: credential.clone(),
        }
    }
}

impl<Credential> AuthenticationScheme for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword,
{
    type Builder = reqwest::blocking::RequestBuilder;
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        builder.basic_auth(self.credential.username(), Some(self.credential.password()))
    }
}

/// Authentication using HTTP Basic authentication to respond to a challenge.
///
/// This currently only supports Basic authentication.
///
/// This limitation is expected to be removed in a future version.
pub struct HttpAuthentication<Credential> {
    credential: Arc<HttpRealmCredentials<Credential>>,
}

impl<Credential> HttpAuthentication<Credential> {
    pub fn new(credential: &Arc<HttpRealmCredentials<Credential>>) -> Self {
        Self {
            credential: credential.clone(),
        }
    }
}

impl<Credential> AuthenticationScheme for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
    type Builder = reqwest::blocking::RequestBuilder;
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;

    fn switch(
        &mut self,
        response: &Self::Response,
    ) -> Result<
        Option<
            Box<
                dyn AuthenticationScheme<
                    Builder = Self::Builder,
                    Request = Self::Request,
                    Response = Self::Response,
                    Error = Self::Error,
                >,
            >,
        >,
        AuthenticError,
    > {
        if response.status() == ::http::StatusCode::UNAUTHORIZED {
            let pw_client = ::http_auth::PasswordClient::try_from(
                response
                    .headers()
                    .get_all(::hyper::header::WWW_AUTHENTICATE),
            )
            .map_err(AuthenticError::Other)?;
            match pw_client {
                http_auth::PasswordClient::Basic(client) => {
                    let realm = client.realm();
                    match self.credential.get_credential(realm) {
                        Some(credential) => {
                            Ok(Some(Box::new(BasicAuthentication::new(credential))))
                        }
                        None => Err(AuthenticError::UnknownRealm(realm.to_owned())),
                    }
                }
                http_auth::PasswordClient::Digest(_) => todo!(),
                _ => todo!(),
            }
        } else {
            Ok(None)
        }
    }
}
