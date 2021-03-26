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
pub const fn generate_response(secret_key: &[u8], challenge: &[u8]) -> Result<Output, Error> {
    if let Err(e) = check_key(secret_key) {
        Err(Error::InvalidKey(e))
    } else if let Err(e) = check_challenge(challenge) {
        Err(Error::InvalidChallenge(e))
    } else {
        Ok(Output {
            buffer: [0; 88],
            len: 0,
        })
    }
}

const fn has_interior_nul(src: &[u8]) -> bool {
    let mut i = 0;
    while i < src.len() {
        if src[i] == 0 {
            return true;
        }
        i += 1;
    }
    false
}

const fn check_key(key: &[u8]) -> Result<(), InvalidKey> {
    if key.is_empty() {
        Err(InvalidKey::ZeroLength)
    } else if key.len() > 256 {
        Err(InvalidKey::TooLong)
    } else if has_interior_nul(key) {
        Err(InvalidKey::InteriorNul)
    } else {
        Ok(())
    }
}

const fn check_challenge(challenge: &[u8]) -> Result<(), InvalidChallenge> {
    if challenge.len() > 64 {
        Err(InvalidChallenge::TooLong)
    } else if has_interior_nul(challenge) {
        Err(InvalidChallenge::InteriorNul)
    } else {
        Ok(())
    }
}
