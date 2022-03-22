use std::borrow::Cow;
use std::sync::Arc;

use crate::credential::{AuthenticationCredentialToken, AuthenticationCredentialUsernamePassword};
use crate::AuthenticationScheme;

pub struct NoAuthentication;

impl NoAuthentication {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

impl AuthenticationScheme for NoAuthentication {
    type Builder = http::request::Builder;
    type Request = hyper::Request<hyper::Body>;
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;
}

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
    type Builder = http::request::Builder;
    type Request = hyper::Request<hyper::Body>;
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        builder.header(self.header_name.as_ref(), self.credential.token())
    }
}

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
    type Builder = http::request::Builder;
    type Request = hyper::Request<hyper::Body>;
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;

    fn configure(&self, builder: Self::Builder) -> Self::Builder {
        let header_value = ::http_auth::basic::encode_credentials(
            self.credential.username(),
            self.credential.password(),
        );
        builder.header(hyper::header::AUTHORIZATION, header_value)
    }
}

pub struct HttpAuthentication<Credential> {
    credential: Arc<Credential>,
}

impl<Credential> HttpAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
    pub fn new(credential: &Arc<Credential>) -> Self {
        Self {
            credential: credential.clone(),
        }
    }
}

impl<Credential> AuthenticationScheme for HttpAuthentication<Credential>
where
    Credential: AuthenticationCredentialUsernamePassword + 'static,
{
    type Builder = http::request::Builder;
    type Request = hyper::Request<hyper::Body>;
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;

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
        if response.status() == ::http::StatusCode::UNAUTHORIZED {
            // TODO: handle www-authenticate, including realms and Digest
            Some(Box::new(BasicAuthentication::new(&self.credential)))
        } else {
            None
        }
    }
}
