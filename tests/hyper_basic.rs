#![cfg(feature = "hyper")]

use authentic::credential::UsernamePasswordCredential;
use authentic::hyper::{HttpAuthentication, BasicAuthentication};
use authentic::{AuthenticateBuilder, AuthenticationScheme, AuthenticationStep, Scheme};
use http::StatusCode;
use hyper::Client;
use hyper_tls::HttpsConnector;

/// Test direct basic authentication, passing the username and password on the first request.
#[::tokio::test]
async fn test_basic_authentication(
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let credential = UsernamePasswordCredential::new("username".into(), "password".into());
    let mut scheme = BasicAuthentication::new(&credential).into_scheme();

    let mut status_codes = Vec::new();

    let response = loop {
        while let Some(auth_step) = scheme.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.request(request).await;
                    scheme.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = ::hyper::Request::get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&scheme)
            .body(::hyper::Body::empty())?;

        dbg!(&request);

        let response = client.request(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        scheme = match scheme.switch(&response) {
            Some(boxed) => Scheme::Boxed(boxed),
            None => break response,
        };
    };

    assert_eq!(status_codes, [StatusCode::OK]);

    Ok(())
}

/// Test basic authentication, passing the username and password in response to a 401 challenge.
#[::tokio::test]
async fn test_basic_challenge(
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let credential = UsernamePasswordCredential::new("username".into(), "password".into());
    let mut scheme = HttpAuthentication::new(&credential).into_scheme();

    let mut status_codes = Vec::new();

    let response = loop {
        while let Some(auth_step) = scheme.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.request(request).await;
                    scheme.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = ::hyper::Request::get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&scheme)
            .body(::hyper::Body::empty())?;

        dbg!(&request);

        let response = client.request(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        scheme = match scheme.switch(&response) {
            Some(boxed) => Scheme::Boxed(boxed),
            None => break response,
        };
    };

    assert_eq!(status_codes, [StatusCode::UNAUTHORIZED, StatusCode::OK]);

    Ok(())
}
