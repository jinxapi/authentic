//! Authentication protocols for use with `reqwest`.
//! Use the `reqwest-async` feature to enable these.

use std::borrow::Cow;
use std::sync::Arc;

use crate::credential::{AuthenticationCredential, FetchedToken, FetchedUsernamePassword};
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
    type Request = reqwest::Request;
    type Response = reqwest::Response;
    type Error = reqwest::Error;
}

impl AuthenticationProtocolConfigure<reqwest::RequestBuilder> for NoAuthentication {}

impl AuthenticationProtocolConfigure<reqwest::Request> for NoAuthentication {}

/// Authentication using a token in a specified header.
pub struct HeaderAuthentication<Credential> {
    header_name: Cow<'static, str>,
    credential: Arc<Credential>,
}

impl<Credential> HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    pub fn new(header_name: impl Into<Cow<'static, str>>, credential: Arc<Credential>) -> Self {
        Self {
            header_name: header_name.into(),
            credential,
        }
    }
}

impl<Credential> AuthenticationProtocol for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    type Request = reqwest::Request;
    type Response = reqwest::Response;
    type Error = reqwest::Error;

    fn step(&self) -> Result<Option<AuthenticationStep<Self::Request>>, AuthenticError> {
        match self.credential.auth_step() {
            Ok(duration) if duration.is_zero() => Ok(None),
            Ok(duration) => Ok(Some(AuthenticationStep::WaitFor(duration))),
            Err(err) => Err(err),
        }
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::RequestBuilder>
    for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    fn configure(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, AuthenticError> {
        let header_name = ::reqwest::header::HeaderName::try_from(self.header_name.as_ref())?;
        let mut header_value =
            ::reqwest::header::HeaderValue::try_from(self.credential.fetch()?.token())?;
        header_value.set_sensitive(true);
        Ok(builder.header(header_name, header_value))
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::Request>
    for HeaderAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    fn configure(&self, mut builder: reqwest::Request) -> Result<reqwest::Request, AuthenticError> {
        let header_name = ::reqwest::header::HeaderName::try_from(self.header_name.as_ref())?;
        let mut header_value =
            ::reqwest::header::HeaderValue::try_from(self.credential.fetch()?.token())?;
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

impl<Credential> BearerAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    pub fn new(credential: Arc<Credential>) -> Self {
        Self {
            auth_scheme: "Bearer".into(),
            credential,
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
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    type Request = reqwest::Request;
    type Response = reqwest::Response;
    type Error = reqwest::Error;

    fn step(&self) -> Result<Option<AuthenticationStep<Self::Request>>, AuthenticError> {
        match self.credential.auth_step() {
            Ok(duration) if duration.is_zero() => Ok(None),
            Ok(duration) => Ok(Some(AuthenticationStep::WaitFor(duration))),
            Err(err) => Err(err),
        }
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::RequestBuilder>
    for BearerAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    fn configure(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, AuthenticError> {
        let fetched = self.credential.fetch()?;
        let token = fetched.token();
        let mut value = Vec::with_capacity(self.auth_scheme.len() + 1 + token.len());
        value.extend(self.auth_scheme.as_bytes());
        value.push(b' ');
        value.extend(token);
        let mut header_value = ::reqwest::header::HeaderValue::try_from(value)?;
        header_value.set_sensitive(true);
        Ok(builder.header(reqwest::header::AUTHORIZATION, header_value))
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::Request>
    for BearerAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedToken,
{
    fn configure(&self, mut builder: reqwest::Request) -> Result<reqwest::Request, AuthenticError> {
        let fetched = self.credential.fetch()?;
        let token = fetched.token();
        let mut value = Vec::with_capacity(self.auth_scheme.len() + 1 + token.len());
        value.extend(self.auth_scheme.as_bytes());
        value.push(b' ');
        value.extend(token);
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
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    pub fn new(credential: Arc<Credential>) -> Self {
        Self { credential }
    }
}

impl<Credential> AuthenticationProtocol for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    type Request = reqwest::Request;
    type Response = reqwest::Response;
    type Error = reqwest::Error;

    fn step(&self) -> Result<Option<AuthenticationStep<Self::Request>>, AuthenticError> {
        match self.credential.auth_step() {
            Ok(duration) if duration.is_zero() => Ok(None),
            Ok(duration) => Ok(Some(AuthenticationStep::WaitFor(duration))),
            Err(err) => Err(err),
        }
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::RequestBuilder>
    for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    fn configure(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, AuthenticError> {
        let fetched = self.credential.fetch()?;
        Ok(builder.basic_auth(fetched.username(), Some(fetched.password())))
    }
}

impl<Credential> AuthenticationProtocolConfigure<reqwest::Request>
    for BasicAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    fn configure(&self, mut builder: reqwest::Request) -> Result<reqwest::Request, AuthenticError> {
        let fetched = self.credential.fetch()?;
        let value = ::http_auth::basic::encode_credentials(fetched.username(), fetched.password());
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
/// Requires feature `loop` (enabled by default).
///
/// This currently only supports Basic authentication.
///
/// This limitation is expected to be removed in a future version.
#[cfg(feature = "loop")]
pub enum HttpAuthentication<Credential> {
    Initial(Arc<crate::credential::HttpRealmCredentials<Credential>>),
    Basic(BasicAuthentication<Credential>),
}

#[cfg(feature = "loop")]
impl<Credential> HttpAuthentication<Credential> {
    pub fn new(credential: Arc<crate::credential::HttpRealmCredentials<Credential>>) -> Self {
        Self::Initial(credential)
    }
}

#[cfg(feature = "loop")]
impl<Credential> AuthenticationProtocol for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    type Request = reqwest::Request;
    type Response = reqwest::Response;
    type Error = reqwest::Error;

    fn step(&self) -> Result<Option<AuthenticationStep<Self::Request>>, AuthenticError> {
        match self {
            Self::Initial(_) => Ok(None),
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
                            let fetched = realm_credentials.fetch()?;
                            match fetched.credential(realm) {
                                Some(credential) => {
                                    *self =
                                        Self::Basic(BasicAuthentication::new(credential.clone()));
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

#[cfg(feature = "loop")]
impl<Credential> AuthenticationProtocolConfigure<reqwest::RequestBuilder>
    for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    fn configure(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, AuthenticError> {
        match self {
            Self::Initial(_) => Ok(builder),
            Self::Basic(basic) => basic.configure(builder),
        }
    }
}

#[cfg(feature = "loop")]
impl<Credential> AuthenticationProtocolConfigure<reqwest::Request>
    for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredential,
    <Credential as AuthenticationCredential>::Fetch: FetchedUsernamePassword,
{
    fn configure(&self, builder: reqwest::Request) -> Result<reqwest::Request, AuthenticError> {
        match self {
            Self::Initial(_) => Ok(builder),
            Self::Basic(basic) => basic.configure(builder),
        }
    }
}
