#![cfg(feature = "reqwest-async")]

use std::sync::Arc;

use authentic::credential::UsernamePasswordCredential;
use authentic::reqwest::BasicAuthentication;
use authentic::{AuthenticationProtocol, AuthenticationStep, WithAuthentication};
use http::StatusCode;

/// Direct basic authentication, passing the username and password on the first request.
/// In this test, the authentication is added to the RequestBuilder.
#[::tokio::test]
async fn test_basic_builder() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = reqwest::Client::new();

    let credential = Arc::new(UsernamePasswordCredential::new("username", "password"));
    let mut authentication = BasicAuthentication::new(credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step()? {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request).await;
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let response = client
            .get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&authentication)?
            .send()
            .await?;

        dbg!(&response);

        status_codes.push(response.status());

        if authentication.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::OK]);

    Ok(())
}

/// Direct basic authentication, passing the username and password on the first request.
/// In this test, the authentication is added to the Request.  This allows the request to
/// be created separately to the client.
#[::tokio::test]
async fn test_basic_request() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = reqwest::Client::new();

    let credential = Arc::new(UsernamePasswordCredential::new("username", "password"));
    let mut authentication = BasicAuthentication::new(credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step()? {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request).await;
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = reqwest::Request::new(
            reqwest::Method::GET,
            reqwest::Url::parse("https://httpbin.org/basic-auth/username/password")?,
        )
        .with_authentication(&authentication)?;

        dbg!(&request);

        let response = client.execute(request).await?;

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
    let client = reqwest::Client::new();

    let mut realm_credentials = std::collections::HashMap::new();
    realm_credentials.insert(
        "Fake Realm".into(),
        Arc::new(UsernamePasswordCredential::new("username", "password")),
    );
    let credential = Arc::new(authentic::credential::HttpRealmCredentials::new(
        realm_credentials,
    ));
    let mut authentication = authentic::reqwest::HttpAuthentication::new(credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step()? {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request).await;
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = client
            .get("https://httpbin.org/basic-auth/username/password")
            .build()?
            .with_authentication(&authentication)?;

        dbg!(&request);

        let response = client.execute(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if authentication.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::UNAUTHORIZED, StatusCode::OK]);

    Ok(())
}
