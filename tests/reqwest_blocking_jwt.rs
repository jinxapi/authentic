#![cfg(all(feature = "reqwest_blocking", feature = "jwt"))]

use std::sync::Arc;
use std::time::Duration;

use authentic::credential::JsonWebTokenCredential;
use authentic::reqwest::blocking::BearerAuthentication;
use authentic::{AuthenticationProtocol, AuthenticationStep, WithAuthentication};

const PRIVATE_KEY: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAyjG6vbJV34K4IisaCs0p9BhuNPJdu/Eeq+EIRLbo3T2QVxhX
ZGCeokIytyEokSa6ok5S3ippo5ZliCWjLwLIbc0jqdavT1Gn3vsF7dzz3z4R6sS8
zxxm5SwKQxF3RTz4BgiITG3RkJQ9ya3QOXHBoQYVUTin89e1goN9MB8CQO1c00J0
cSV/NtvW8KUNEHxPmT/FYR/aiYC71f7eEO3AYKsOdUqo73rt53V39rJANcY7OyhN
4HuTYu9AtpELNcE7YR02REspCnNrPYbG7G4QCrpZ4eRNA1HRW/pQfltvxh92tSmN
rAkDj/a6zNFDTaXODZt0YMSs9au4WQxVAarO9wIDAQABAoIBAHpTJbgYSU2kxwOc
8e9w+h28HgiYTM8kbDruNNNlmXIoCcg3aL/ImJBv3kDepa1TMfx5yDaykCCxH5ID
uzr4wwty3U2mHX+uVhJX6dljIIOCCNLw3Y2rkDC7uSWkTnUsEp2L0fHzSqLenJcE
OgJW6R8jEAiIb0vdx+lC5Z0UVYezPt4lIAR8vcAjANJTbk5aVx6XcAg5AC8pl0mT
SAzG36XbaPemt4tt1ZB2IoJp3z+3xLWuGYJcCvGU7qx8qHS07D3hnw1wegR8c6Lm
7DUz2BN/KMNijOzCjUhq3mVzeJsit2z/MNatqkLoLv44pnfKZHqRDM/SsZC6zLK7
pPQfZxkCgYEA8xd/HprbZK6DbaD28kAl4jQw33TjTumudx4NfPJYFytt3jbPelpy
qDpqwpejPjWxIvq4eaGsxk6C0mmqbCT1wkQwcik+WyQmia/lxhjySLkz+sanLIVh
hGTu9/2o6Fftgm8aSYe757BvBbiLOlF0DRhqfmOOuwUqDc9iVPEcu20CgYEA1O5J
UqMW+Mp4Ne76JAW8h6Q5/gcW63qRYfC2bRIDlTNVfGmw8FbLTU/wU6cZe5GkI6Nr
KokdKeCVd7zA/GGd5wAGl9T8RA6CZJ8AC2UUru+YYkeRcui/geWamcv9Q7PhN25j
8JmW70egvzUC2WCaTFaAqNBBlyMDu5YalJ718XMCgYBvfA8okgycGAzecjvOzeyR
2S2wzYKR5knFB1tYOix8M8anaqusiV6cGG5t3+1V0nnyeNmxrpv2Nnt41Ez8W9b5
yRwOvyuB0Qp7itfuCfLTt1xHXmO8307h0QhnY0XbiLe8YgfEQSPEFf5UuVXg4QpA
Fzp/zFjhHHU08C9AlXN/4QKBgDHvI6DOgE+d46z6Ow0Bj2Hb4IGzFevpFXj7YzyW
0eJGZJDFlGn4YLrjuT9U24P/9pco9rPF7eHpOgQXbsaA+e+3MNSgbPxkzq1cID2L
2drgc0Lw96oT7P1AZA4XKXCcGX/PUn6U9jFtAcR1YRKrNeQbERcFp6wS2Qg/vkIG
OTUDAoGANvD8R1sXTsp4JKSlerLPKARAFZxG8lxl+izGZh7LBr1EJHJshA6fkbFf
qdYvM9L9WK8+sYxveLl5CaVvqqDdYsBYx5TQ/MAsOmuYS27WwfLYBFvAuycPtGnx
uhFkBJn+pPZu8NiWCEDGq6xd3s/93jLWMTaS5PncRcMHpKpO72M=
-----END RSA PRIVATE KEY-----
";

/// JWT authentication.
#[test]
fn test_jwt() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();

    // Expiration time resolution is 1 second, so we need to wait at least that
    // long to get a different JWT.
    let expiration = Duration::from_secs(1);

    let credential = Arc::new(JsonWebTokenCredential::new(
        jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY)?,
        expiration,
    ));

    let mut authentication = BearerAuthentication::new(credential.clone());

    while let Some(auth_step) = authentication.step()? {
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
        .get("https://example.com")
        .build()?
        .with_authentication(&authentication)?;

    let auth1 = request
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .unwrap()
        .to_str()?;

    let mut authentication = BearerAuthentication::new(credential.clone());

    while let Some(auth_step) = authentication.step()? {
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
        .get("https://example.com")
        .build()?
        .with_authentication(&authentication)?;

    let auth2 = request
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .unwrap()
        .to_str()?;

    assert_eq!(auth1, auth2);

    // Wait for JWT to expire
    std::thread::sleep(expiration);

    let mut authentication = BearerAuthentication::new(credential.clone());

    while let Some(auth_step) = authentication.step()? {
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
        .get("https://example.com")
        .build()?
        .with_authentication(&authentication)?;

    let auth3 = request
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .unwrap()
        .to_str()?;

    assert_ne!(auth1, auth3);

    Ok(())
}
