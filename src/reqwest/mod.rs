//! Authentication protocols for use with `reqwest`.
//! Use the `reqwest-async` feature to enable these.

// The async feature uses `mod` and `use` to position the code in the `crate::reqwest` module.
// The blocking feature only uses `mod` to position the code in the `crate::reqwest::blocking` module.
// This reflects the pattern used in the `rewest` crate.

#[cfg(feature = "reqwest-async")]
mod asynch;

#[cfg(feature = "reqwest-async")]
pub use asynch::*;

#[cfg(feature = "reqwest-blocking")]
pub mod blocking;
