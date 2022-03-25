use http::header::HeaderName;
use http::HeaderValue;

pub trait SetSensitiveHeader<V> {
    fn set_sensitive_header<K>(self, key: K, value: V) -> Self
    where
        Self: Sized,
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>;
}

// Fluent interface, HeaderValue TryFrom, sensitive - pick any two. If the TryFrom
// succeeds, we're good. Otherwise, add the header without conversion so the second
// `try_from` gets the error into the internal state of the RequestBuilder. Related
// but closed issue: https://github.com/seanmonstar/reqwest/issues/1378

#[cfg(feature = "reqwest")]
impl<V> SetSensitiveHeader<V> for reqwest::RequestBuilder
where
    V: Copy,
{
    fn set_sensitive_header<K>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        match HeaderValue::try_from(value) {
            Ok(mut header_value) => {
                header_value.set_sensitive(true);
                self.header::<K, HeaderValue>(key, header_value)
            }
            Err(_) => self.header(key, value),
        }
    }
}

#[cfg(feature = "reqwest_blocking")]
impl<V> SetSensitiveHeader<V> for reqwest::blocking::RequestBuilder
where
    V: Copy,
{
    fn set_sensitive_header<K>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        match HeaderValue::try_from(value) {
            Ok(mut header_value) => {
                header_value.set_sensitive(true);
                self.header::<K, HeaderValue>(key, header_value)
            }
            Err(_) => self.header(key, value),
        }
    }
}

// Unlike reqwest, hyper does let us access the header values after conversion.
// So we could add the header with conversion, and then lookup the header value
// to set sensitive. This would require cloning the key.
//
// However, for consistency, use the same solution as reqwest. It's fast when TryFrom
// succeeds.
#[cfg(feature = "hyper")]
impl<V> SetSensitiveHeader<V> for ::http::request::Builder
where
    V: Copy,
{
    fn set_sensitive_header<K>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        match HeaderValue::try_from(value) {
            Ok(mut header_value) => {
                header_value.set_sensitive(true);
                self.header::<K, HeaderValue>(key, header_value)
            }
            Err(_) => self.header(key, value),
        }
    }
}
