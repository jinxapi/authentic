# authentic

A Rust crate to handle authentication of HTTP calls.  Documentation at https://docs.rs/authentic/latest/authentic/.

Authentication protocols can require specific workflows, such as making third-party calls to refresh a token or performing an initial request to get challenge information.

Using a fixed code structure, `authentic` can perform the necessary interactions for each authentication protocol. This allows protocols to be changed easily.

For example, the following code uses `reqwest` to access a site using HTTP Basic authentication. (See the [repository tests directory](https://github.com/jinxapi/authentic/tree/main/tests) for fully working examples).

```rust
// One-time code:
let client = ::reqwest::blocking::Client::new();

let mut realm_credentials = HashMap::new();
realm_credentials.insert(
    "Fake Realm".into(),
    UsernamePasswordCredential::new("username", "password"),
);
let credential = HttpRealmCredentials::new(realm_credentials);

// Per-request code:
let mut authentication = HttpAuthentication::new(&credential);
let response = loop {
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

    let response = client
        .get("https://httpbin.org/basic-auth/username/password")
        .with_authentication(&authentication)?
        .send()?;

    if authentication.has_completed(&response)? {
        break response;
    }
};
```

The creation of the request takes place inside a loop. First, the authentication protocol is given an opportunity to perform any third-party calls using `step()`.
HTTP Basic authentication does not use this, but it can be used, for example, to refresh an expired OAuth2 access token.

The request is created using a standard `reqwest::RequestBuilder`, using a new `with_authentication()` method to modify the request for the authentication protocol.
For HTTP authentication, the first iteration makes no change to the request.

The request is sent and a response is received.  For HTTP authentication, this returns a `401 Unauthorized` response.

The `has_completed()` method checks if the response is ready to be returned or if the authentication protocol needs to retry.
For HTTP authentication, this reads the returned `www-authenticate` challenge and establishes the correct credentials.
As the request needs to be retried, `has_completed()` returns `false` and a second iteration begins.

On the second iteration of the loop, `with_authentication()` adds the credentials as the `Authorization` header to the request. The request is authenticated and the response contains the correct data. `has_completed()` will return `true` and the loop exits with the response.
