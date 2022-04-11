#![cfg(feature = "reqwest_blocking")]

use std::collections::HashMap;

use authentic::credential::{HttpRealmCredentials, UsernamePasswordCredential};
use authentic::reqwest::blocking::{BasicAuthentication, HttpAuthentication};
use authentic::{AuthenticationProtocol, AuthenticationStep, WithAuthentication};
use http::StatusCode;

/// Direct basic authentication, passing the username and password on the first request.
/// In this test, the authentication is added to the RequestBuilder.
#[test]
fn test_basic_builder() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();

    let credential = UsernamePasswordCredential::new("username", "password");
    let mut authentication = BasicAuthentication::new(&credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request);
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    std::thread::sleep(duration);
                }
            }
        }
        let response = client
            .get("https://httpbin.org/basic-auth/username/password")
            .with_authentication(&authentication)?
            .send()?;

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
#[test]
fn test_basic_request() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();

    let credential = UsernamePasswordCredential::new("username", "password");
    let mut authentication = BasicAuthentication::new(&credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request);
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    std::thread::sleep(duration);
                }
            }
        }
        let request = reqwest::blocking::Request::new(
            reqwest::Method::GET,
            reqwest::Url::parse("https://httpbin.org/basic-auth/username/password")?,
        )
        .with_authentication(&authentication)?;

        dbg!(&request);

        let response = client.execute(request)?;

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
#[test]
fn test_basic_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();

    let mut realm_credentials = HashMap::new();
    realm_credentials.insert(
        "Fake Realm".into(),
        UsernamePasswordCredential::new("username", "password"),
    );
    let credential = HttpRealmCredentials::new(realm_credentials);
    let mut authentication = HttpAuthentication::new(&credential);

    let mut status_codes = Vec::new();

    let _response = loop {
        while let Some(auth_step) = authentication.step() {
            match auth_step {
                AuthenticationStep::Request(request) => {
                    let auth_response = client.execute(request);
                    authentication.respond(auth_response);
                }
                AuthenticationStep::WaitFor(duration) => {
                    std::thread::sleep(duration);
                }
            }
        }
        let request = client
            .get("https://httpbin.org/basic-auth/username/password")
            .build()?
            .with_authentication(&authentication)?;

        dbg!(&request);

        let response = client.execute(request)?;

        dbg!(&response);

        status_codes.push(response.status());

        if authentication.has_completed(&response)? {
            break response;
        }
    };

    assert_eq!(status_codes, [StatusCode::UNAUTHORIZED, StatusCode::OK]);

    Ok(())
}
