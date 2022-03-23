#![cfg(feature = "reqwest")]

use ::reqwest::Client;
use authentic::credential::UsernamePasswordCredential;
use authentic::reqwest::{BasicAuthentication, HttpAuthentication};
use authentic::{AuthenticateBuilder, AuthenticationScheme, AuthenticationStep};
use http::StatusCode;

/// Test direct basic authentication, passing the username and password on the first request.
#[::tokio::test]
async fn test_basic_authentication(
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = Client::new();

    let credential = UsernamePasswordCredential::new("username".into(), "password".into());
    let mut scheme = BasicAuthentication::new(&credential).into_scheme();

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = scheme.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request).await;
                    scheme.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = client
            .get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&scheme)
            .build()?;

        dbg!(&request);

        let response = client.execute(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if scheme.has_completed(&response) {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::OK]);

    Ok(())
}

/// Test basic authentication, passing the username and password in response to a 401 challenge.
#[::tokio::test]
async fn test_basic_challenge() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = Client::new();

    let credential = UsernamePasswordCredential::new("username".into(), "password".into());
    let mut scheme = HttpAuthentication::new(&credential).into_scheme();

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = scheme.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request).await;
                    scheme.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    ::tokio::time::sleep(duration).await;
                }
            }
        }
        let request = client
            .get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&scheme)
            .build()?;

        dbg!(&request);

        let response = client.execute(request).await?;

        dbg!(&response);

        status_codes.push(response.status());

        if scheme.has_completed(&response) {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::UNAUTHORIZED, StatusCode::OK]);

    Ok(())
}
