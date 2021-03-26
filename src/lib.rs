// Copyright (c) 2021 FaultyRAM
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option. This file may not be copied,
// modified, or distributed except according to those terms.

//! Generates responses to a GameSpy protocol secure/validate challenge.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    clippy::all,
    clippy::pedantic,
    warnings,
    future_incompatible,
    rust_2018_idioms,
    rustdoc,
    unused
)]

#[cfg(not(feature = "std"))]
use core as std_crate;
#[cfg(feature = "std")]
use std as std_crate;

mod error;

pub use error::{Error, InvalidChallenge, InvalidKey};

/// The generated response to a secure/validate challenge.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    buffer: [u8; 88],
    len: usize,
}

/// Generates a secure/validate response from a secret key and challenge.
///
/// # Errors
///
/// This function returns an `Error` if the secret key or challenge are invalid:
///
/// * `Error::InvalidKey` if the secret key is invalid; the inner `InvalidKey` specifies the exact
///   problem
/// * `Error::InvalidChallenge` if the challenge is invalid; the inner `InvalidChallenge` specifies
///   the exact problem
pub const fn generate_response(_secret_key: &[u8], _challenge: &[u8]) -> Result<Output, Error> {
    Ok(Output {
        buffer: [0; 88],
        len: 0,
    })
}
