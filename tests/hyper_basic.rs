#![cfg(feature = "hyper")]

use std::sync::Arc;

use authentic::credential::UsernamePasswordCredential;
use authentic::hyper::BasicAuthentication;
use authentic::{AuthenticationProtocol, AuthenticationStep, WithAuthentication};
use http::StatusCode;
use hyper::Client;
use hyper_tls::HttpsConnector;

/// Direct basic authentication, passing the username and password on the first request.
/// This test can run without the `loop` feature to demonstrate non-looping authentication.
#[::tokio::test]
async fn test_basic_authentication(
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let credential = Arc::new(UsernamePasswordCredential::new("username", "password"));
    let mut authentication = BasicAuthentication::new(credential);

    while let Some(auth_step) = authentication.step()? {
        match auth_step {
            AuthenticationStep::Request(request) => {
                let auth_response = client.request(request).await;
                authentication.respond(auth_response);
            }
            AuthenticationStep::WaitFor(duration) => {
                ::tokio::time::sleep(duration).await;
            }
        }
    }
    let request = ::hyper::Request::get("https://httpbin.org/basic-auth/username/password")
        .with_authentication(&authentication)?
        .body(::hyper::Body::empty())?;

    dbg!(&request);

    let response = client.request(request).await?;

    dbg!(&response);

    assert!(authentication.has_completed(&response)?);

    assert_eq!(response.status(), StatusCode::OK);

    Ok(())
}

/// Direct basic authentication, passing the username and password on the first request.
#[::tokio::test]
async fn test_basic_authentication_loop(
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let credential = Arc::new(UsernamePasswordCredential::new("username", "password"));
    let mut authentication = BasicAuthentication::new(credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step()? {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.request(request).await;
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = ::hyper::Request::get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&authentication)?
            .body(::hyper::Body::empty())?;

        dbg!(&request);

        let response = client.request(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if authentication.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::OK]);

    Ok(())
}

/// Basic authentication passing the username and password in response to a 401 challenge.
///
/// `HttpAuthentication` is only supported with the `loop` feature.
#[cfg(feature = "loop")]
#[::tokio::test]
async fn test_basic_challenge() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, ::hyper::Body>(https);

    let mut realm_credentials = std::collections::HashMap::new();
    realm_credentials.insert(
        "Fake Realm".into(),
        Arc::new(UsernamePasswordCredential::new("username", "password")),
    );
    let credential = Arc::new(authentic::credential::HttpRealmCredentials::new(
        realm_credentials,
    ));
    let mut authentication = authentic::hyper::HttpAuthentication::new(credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step()? {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.request(request).await;
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = ::hyper::Request::get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&authentication)?
            .body(::hyper::Body::empty())?;

        dbg!(&request);

        let response = client.request(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if authentication.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::UNAUTHORIZED, StatusCode::OK]);

    Ok(())
}
