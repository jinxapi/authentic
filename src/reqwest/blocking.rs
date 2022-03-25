//! Authentication schemes for use with blocking `reqwest`.
//! Use the `reqwest_blocking` feature to enable these.

use std::borrow::Cow;
use std::sync::Arc;

use crate::credential::{
    AuthenticationCredentialToken, AuthenticationCredentialUsernamePassword, HttpRealmCredentials,
};
use crate::sensitive::SetSensitiveHeader;
use crate::{AuthenticError, AuthenticationScheme, AuthenticationStep};

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
        builder.set_sensitive_header(self.header_name.as_ref(), self.credential.token())
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
pub enum HttpAuthentication<Credential> {
    Initial(Arc<HttpRealmCredentials<Credential>>),
    Basic(BasicAuthentication<Credential>),
}

impl<Credential> HttpAuthentication<Credential> {
    pub fn new(credential: &Arc<HttpRealmCredentials<Credential>>) -> Self {
        Self::Initial(credential.clone())
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

    fn step(&mut self) -> Option<AuthenticationStep<Self::Request>> {
        match self {
            Self::Initial(_) => None,
            Self::Basic(basic) => basic.step(),
        }
    }

    fn respond(&mut self, response: Result<Self::Response, Self::Error>) {
        match self {
            Self::Initial(_) => unimplemented!(),
            Self::Basic(basic) => basic.respond(response),
        }
    }

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        match self {
            Self::Initial(_) => builder,
            Self::Basic(basic) => basic.configure(builder),
        }
    }

    fn has_completed(&mut self, response: &Self::Response) -> Result<bool, AuthenticError> {
        match self {
            Self::Initial(realm_credentials) => {
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
                            match realm_credentials.get_credential(realm) {
                                Some(credential) => {
                                    *self = Self::Basic(BasicAuthentication::new(credential));
                                    Ok(false)
                                }
                                None => Err(AuthenticError::UnknownRealm(realm.to_owned())),
                            }
                        }
                        http_auth::PasswordClient::Digest(_) => todo!(),
                        _ => todo!(),
                    }
                } else {
                    Ok(true)
                }
            }
            Self::Basic(basic) => basic.has_completed(response)
        }
    }
}
