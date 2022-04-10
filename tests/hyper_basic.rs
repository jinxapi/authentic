#![cfg(feature = "hyper")]

use std::collections::HashMap;

use authentic::credential::{HttpRealmCredentials, UsernamePasswordCredential};
use authentic::hyper::{BasicAuthentication, HttpAuthentication};
use authentic::{AuthenticationProtocol, AuthenticationStep, WithAuthentication};
use http::StatusCode;
use hyper::Client;
use hyper_tls::HttpsConnector;

/// Direct basic authentication, passing the username and password on the first request.
#[::tokio::test]
async fn test_basic_authentication(
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let credential = UsernamePasswordCredential::new("username", "password");
    let mut scheme = BasicAuthentication::new(&credential);

    let mut status_codes = Vec::new();

    let _response = loop {
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
            .with_authentication(&scheme)?
            .body(::hyper::Body::empty())?;

        dbg!(&request);

        let response = client.request(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if scheme.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::OK]);

    Ok(())
}

/// Basic authentication passing the username and password in response to a 401 challenge.
#[::tokio::test]
async fn test_basic_challenge() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let mut realm_credentials = HashMap::new();
    realm_credentials.insert(
        "Fake Realm".into(),
        UsernamePasswordCredential::new("username", "password"),
    );
    let credential = HttpRealmCredentials::new(realm_credentials);
    let mut scheme = HttpAuthentication::new(&credential);

    let mut status_codes = Vec::new();

    let _response = loop {
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
            .with_authentication(&scheme)?
            .body(::hyper::Body::empty())?;

        dbg!(&request);

        let response = client.request(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if scheme.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::UNAUTHORIZED, StatusCode::OK]);

    Ok(())
}
