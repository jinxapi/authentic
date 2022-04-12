//! Authentication protocols for use with blocking `reqwest`.
//! Use the `reqwest_blocking` feature to enable these.

use std::borrow::Cow;
use std::sync::Arc;

use crate::credential::{
    AuthenticationCredentialToken, AuthenticationCredentialUsernamePassword, HttpRealmCredentials,
};
use crate::{
    AuthenticError, AuthenticationProtocol, AuthenticationProtocolConfigure, AuthenticationStep,
};

/// Protocol for no authentication
///
/// Identical to not using `authentic` but allows minimal code changes when changing protocols.
pub struct NoAuthentication;

impl NoAuthentication {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

impl AuthenticationProtocol for NoAuthentication {
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;
}

impl AuthenticationProtocolConfigure<reqwest::blocking::RequestBuilder> for NoAuthentication {}

impl AuthenticationProtocolConfigure<reqwest::blocking::Request> for NoAuthentication {}

/// Authentication using a token in a specified header.
pub struct HeaderAuthentication<Credential> {
    header_name: Cow<'static, str>,
    credential: Arc<Credential>,
}

impl<Credential: 'static> HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    pub fn new(header_name: impl Into<Cow<'static, str>>, credential: &Arc<Credential>) -> Self {
        Self {
            header_name: header_name.into(),
            credential: credential.clone(),
        }
    }
}

impl<Credential> AuthenticationProtocol for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::RequestBuilder>
    for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    fn configure(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::RequestBuilder, AuthenticError> {
        let header_name = ::reqwest::header::HeaderName::try_from(self.header_name.as_ref())?;
        let mut header_value =
            ::reqwest::header::HeaderValue::try_from(self.credential.token()?.as_slice())?;
        header_value.set_sensitive(true);
        Ok(builder.header(header_name, header_value))
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::Request>
    for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    fn configure(
        &self,
        mut builder: reqwest::blocking::Request,
    ) -> Result<reqwest::blocking::Request, AuthenticError> {
        let header_name = ::reqwest::header::HeaderName::try_from(self.header_name.as_ref())?;
        let mut header_value =
            ::reqwest::header::HeaderValue::try_from(self.credential.token()?.as_slice())?;
        header_value.set_sensitive(true);
        builder.headers_mut().append(header_name, header_value);
        Ok(builder)
    }
}

/// Authentication using a bearer token in the HTTP Authorization header.
pub struct BearerAuthentication<Credential> {
    auth_scheme: Cow<'static, str>,
    credential: Arc<Credential>,
}

impl<Credential: 'static> BearerAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    pub fn new(credential: &Arc<Credential>) -> Self {
        Self {
            auth_scheme: "Bearer".into(),
            credential: credential.clone(),
        }
    }

    /// Change the default `Bearer` scheme to another string.
    ///
    /// Some systems use a bearer token, but use a scheme name other
    /// than `Bearer`.
    pub fn with_auth_scheme(mut self, auth_scheme: impl Into<Cow<'static, str>>) -> Self {
        self.auth_scheme = auth_scheme.into();
        self
    }
}

impl<Credential> AuthenticationProtocol for BearerAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::RequestBuilder>
    for BearerAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    fn configure(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::RequestBuilder, AuthenticError> {
        let token = self.credential.token()?;
        let mut value = Vec::with_capacity(self.auth_scheme.len() + 1 + token.len());
        value.extend(self.auth_scheme.as_bytes());
        value.push(b' ');
        value.extend(token.as_slice());
        let mut header_value = ::reqwest::header::HeaderValue::try_from(value)?;
        header_value.set_sensitive(true);
        Ok(builder.header(reqwest::header::AUTHORIZATION, header_value))
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::Request>
    for BearerAuthentication<Credential>
where
    Credential: AuthenticationCredentialToken,
{
    fn configure(
        &self,
        mut builder: reqwest::blocking::Request,
    ) -> Result<reqwest::blocking::Request, AuthenticError> {
        let token = self.credential.token()?;
        let mut value = Vec::with_capacity(self.auth_scheme.len() + 1 + token.len());
        value.extend(self.auth_scheme.as_bytes());
        value.push(b' ');
        value.extend(token.as_slice());
        let mut header_value = ::reqwest::header::HeaderValue::try_from(value)?;
        header_value.set_sensitive(true);
        builder
            .headers_mut()
            .append(reqwest::header::AUTHORIZATION, header_value);
        Ok(builder)
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

impl<Credential> AuthenticationProtocol for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword,
{
    type Request = reqwest::blocking::Request;
    type Response = reqwest::blocking::Response;
    type Error = reqwest::Error;
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::RequestBuilder>
    for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword,
{
    fn configure(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::RequestBuilder, AuthenticError> {
        Ok(builder.basic_auth(self.credential.username(), Some(self.credential.password())))
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::Request>
    for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword,
{
    fn configure(
        &self,
        mut builder: reqwest::blocking::Request,
    ) -> Result<reqwest::blocking::Request, AuthenticError> {
        let value = ::http_auth::basic::encode_credentials(
            self.credential.username(),
            self.credential.password(),
        );
        let mut header_value = ::reqwest::header::HeaderValue::try_from(value)?;
        header_value.set_sensitive(true);
        builder
            .headers_mut()
            .append(reqwest::header::AUTHORIZATION, header_value);
        Ok(builder)
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

impl<Credential> AuthenticationProtocol for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
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

    fn has_completed(&mut self, response: &Self::Response) -> Result<bool, AuthenticError> {
        match self {
            Self::Initial(realm_credentials) => {
                if response.status() == ::http::StatusCode::UNAUTHORIZED {
                    let pw_client = ::http_auth::PasswordClient::try_from(
                        response
                            .headers()
                            .get_all(::reqwest::header::WWW_AUTHENTICATE),
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
            Self::Basic(basic) => basic.has_completed(response),
        }
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::RequestBuilder>
    for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
    fn configure(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::RequestBuilder, AuthenticError> {
        match self {
            Self::Initial(_) => Ok(builder),
            Self::Basic(basic) => basic.configure(builder),
        }
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::blocking::Request>
    for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
    fn configure(
        &self,
        builder: reqwest::blocking::Request,
    ) -> Result<reqwest::blocking::Request, AuthenticError> {
        match self {
            Self::Initial(_) => Ok(builder),
            Self::Basic(basic) => basic.configure(builder),
        }
    }
}
