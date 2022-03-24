//! # authentic
//!
//! Handle authentication of HTTP calls.
//!
//! Authentication schemes can require specific workflows, such as making third-party calls to refresh a token or performing an initial request to get challenge information.
//!
//! Using a fixed code structure, `authentic` can perform the necessary interactions for each authentication scheme. This allows schemes to be changed easily.
//!
//! For example, the following code uses `reqwest` to access a site using HTTP Basic authentication. (See the [repository tests directory](https://github.com/jinxapi/authentic/tree/main/tests) for fully working examples).
//!
//! ```ignore
//! // One-time code:
//! let client = ::reqwest::blocking::Client::new();
//!
//! let mut realm_credentials = HashMap::new();
//! realm_credentials.insert(
//!     "Fake Realm".into(),
//!     UsernamePasswordCredential::new("username", "password"),
//! );
//! let credential = HttpRealmCredentials::new(realm_credentials);
//!
//! // Per-request code:
//! let mut scheme = HttpAuthentication::new(&credential).into_scheme();
//! let response = loop {
//!     while let Some(auth_step) = scheme.step() {
//!         match auth_step {
//!             AuthenticationStep::Request(request) => {
//!                 let auth_response = client.execute(request);
//!                 scheme.respond(auth_response);
//!             }
//!             AuthenticationStep::WaitFor(duration) => {
//!                 std::thread::sleep(duration);
//!             }
//!         }
//!     }
//!
//!     let request = client
//!         .get("https://httpbin.org/basic-auth/username/password")
//!         .with_authentication(&scheme)
//!         .build()?;
//!
//!     let response = client.execute(request)?;
//!
//!     if scheme.has_completed(&response)? {
//!         break response;
//!     }
//! };
//! ```
//!
//! The creation of the request takes place inside a loop. First, the authentication scheme is given an opportunity to perform any third-party calls using `step()`.
//! HTTP Basic authentication does not use this, but it can be used, for example, to refresh an expired OAuth2 access token.
//!
//! The request is created using a standard `reqwest` RequestBuilder, using a new `with_authentication()` method to modify the request for the authentication scheme.
//! For HTTP authentication, the first iteration makes no change to the request.
//!
//! The request is sent and a response is received.  For HTTP authentication, this returns a `401 Unauthorized` response.
//!
//! The `has_completed()` method checks if the response is ready to be returned or if the authentication scheme needs to retry.
//! For HTTP authentication, this reads the returned `www-authenticate` challenge and establishes the correct credentials.
//! As the request needs to be retried, `has_completed()` returns `false` and a second iteration begins.
//!
//! On the second iteration of the loop, `with_authentication()` adds the credentials as the `Authorization` header to the request. The request is authenticated and the response contains the correct data. `has_completed()` will return `true` and the loop exits with the response.

use std::time::Duration;

use thiserror::Error;

pub mod credential;

#[cfg(feature = "hyper")]
pub mod hyper;
#[cfg(feature = "reqwest")]
pub mod reqwest;

#[derive(Error, Debug)]
pub enum AuthenticError {
    #[error("No credentials found for realm {0:?}")]
    UnknownRealm(String),
    #[error("{0}")]
    Other(String),
}

pub enum AuthenticationStep<Request> {
    Request(Request),
    WaitFor(Duration),
}

pub trait AuthenticationProcess {
    fn auth_step<Request>(&mut self) -> Option<AuthenticationStep<Request>> {
        None
    }

    fn auth_response<Response, Error>(
        &mut self,
        #[allow(unused_variables)] response: Result<Response, Error>,
    ) {
        panic!("Unexpected auth response");
    }
}

pub trait AuthenticationScheme {
    type Builder;
    type Request;
    type Response;
    type Error;

    fn into_scheme(self) -> Scheme<Self, Self::Builder, Self::Request, Self::Response, Self::Error>
    where
        Self: Sized,
    {
        Scheme::Initial(self)
    }

    fn step(&mut self) -> Option<AuthenticationStep<Self::Request>> {
        None
    }

    fn respond(
        &mut self,
        #[allow(unused_variables)] response: Result<Self::Response, Self::Error>,
    ) {
        panic!("Unexpected auth response");
    }

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        builder
    }

    #[allow(clippy::type_complexity)]
    fn switch(
        &mut self,
        #[allow(unused_variables)] response: &Self::Response,
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
        Ok(None)
    }
}

// Allow request builder authentication to use fluent model.
pub trait WithAuthentication<Request, Response, Error>
where
    Self: Sized,
{
    #[must_use]
    fn with_authentication(
        self,
        scheme: &dyn AuthenticationScheme<
            Builder = Self,
            Request = Request,
            Response = Response,
            Error = Error,
        >,
    ) -> Self {
        scheme.configure(self)
    }
}

#[cfg(feature = "hyper")]
impl
    WithAuthentication<
        ::hyper::Request<::hyper::Body>,
        ::hyper::Response<::hyper::Body>,
        ::hyper::Error,
    > for http::request::Builder
{
}

#[cfg(feature = "reqwest")]
impl WithAuthentication<::reqwest::Request, ::reqwest::Response, ::reqwest::Error>
    for ::reqwest::RequestBuilder
{
}

#[cfg(feature = "reqwest_blocking")]
impl
    WithAuthentication<
        ::reqwest::blocking::Request,
        ::reqwest::blocking::Response,
        ::reqwest::Error,
    > for ::reqwest::blocking::RequestBuilder
{
}

/// Type to allow initial scheme to avoid allocation.
///
/// Switching uses boxed trait objects to allow the scheme to be changed.  However, this
/// allocates even for simple schemes that never switch.
///
/// Scheme is an enum containing the initial scheme or a boxed trait object.
pub enum Scheme<Initial, Builder, Request, Response, Error>
where
    Initial: AuthenticationScheme<
        Builder = Builder,
        Request = Request,
        Response = Response,
        Error = Error,
    >,
{
    Initial(Initial),
    Boxed(
        Box<
            dyn AuthenticationScheme<
                Builder = Builder,
                Request = Request,
                Response = Response,
                Error = Error,
            >,
        >,
    ),
}

impl<Initial, Builder, Request, Response, Error> Scheme<Initial, Builder, Request, Response, Error>
where
    Initial: AuthenticationScheme<
        Builder = Builder,
        Request = Request,
        Response = Response,
        Error = Error,
    >,
{
    pub fn has_completed(&mut self, response: &Response) -> Result<bool, AuthenticError> {
        match self.switch(response)? {
            Some(boxed) => {
                *self = Scheme::Boxed(boxed);
                Ok(false)
            }
            None => Ok(true),
        }
    }
}

impl<T, Builder, Request, Response, Error> AuthenticationScheme
    for Scheme<T, Builder, Request, Response, Error>
where
    T: AuthenticationScheme<
        Builder = Builder,
        Request = Request,
        Response = Response,
        Error = Error,
    >,
{
    type Builder = Builder;
    type Request = Request;
    type Response = Response;
    type Error = Error;

    fn step(&mut self) -> Option<AuthenticationStep<Self::Request>> {
        match self {
            Scheme::Initial(scheme) => scheme.step(),
            Scheme::Boxed(scheme) => scheme.step(),
        }
    }

    fn respond(&mut self, response: Result<Self::Response, Self::Error>) {
        match self {
            Scheme::Initial(scheme) => scheme.respond(response),
            Scheme::Boxed(scheme) => scheme.respond(response),
        }
    }

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        match self {
            Scheme::Initial(scheme) => scheme.configure(builder),
            Scheme::Boxed(scheme) => scheme.configure(builder),
        }
    }

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
        match self {
            Scheme::Initial(scheme) => scheme.switch(response),
            Scheme::Boxed(scheme) => scheme.switch(response),
        }
    }
}
