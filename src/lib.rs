use std::time::Duration;

use thiserror::Error;

pub mod credential;

#[cfg(feature = "hyper")]
pub mod hyper;
#[cfg(feature = "reqwest")]
pub mod reqwest;

#[derive(Error, Debug)]
pub enum AuthenticateError {
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

    fn auth_response<Response, Error>(&mut self, response: Result<Response, Error>) {
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

    fn respond(&mut self, response: Result<Self::Response, Self::Error>) {
        panic!("Unexpected auth response");
    }

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        builder
    }

    #[allow(clippy::type_complexity)]
    fn switch(
        &mut self,
        response: &Self::Response,
    ) -> Option<
        Box<
            dyn AuthenticationScheme<
                Builder = Self::Builder,
                Request = Self::Request,
                Response = Self::Response,
                Error = Self::Error,
            >,
        >,
    > {
        None
    }
}

// Allow request builder authentication to use fluent model.
pub trait AuthenticateBuilder<Request, Response, Error>
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
impl AuthenticateBuilder<::hyper::Request<::hyper::Body>, ::hyper::Response<::hyper::Body>, ::hyper::Error>
    for http::request::Builder
{
}

#[cfg(feature = "reqwest")]
impl AuthenticateBuilder<::reqwest::Request, ::reqwest::Response, ::reqwest::Error>
    for ::reqwest::RequestBuilder
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
    ) -> Option<
        Box<
            dyn AuthenticationScheme<
                Builder = Self::Builder,
                Request = Self::Request,
                Response = Self::Response,
                Error = Self::Error,
            >,
        >,
    > {
        match self {
            Scheme::Initial(scheme) => scheme.switch(response),
            Scheme::Boxed(scheme) => scheme.switch(response),
        }
    }
}
