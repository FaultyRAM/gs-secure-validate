// Copyright (c) 2021 FaultyRAM
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option. This file may not be copied,
// modified, or distributed except according to those terms.

#[cfg(feature = "std")]
use crate::std_crate::error;
use crate::std_crate::fmt::{self, Display, Formatter};

/// Represents errors arising from this crate.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// The provided secret key is invalid.
    InvalidKey(InvalidKey),
    /// The provided challenge is invalid.
    InvalidChallenge(InvalidChallenge),
}

/// Represents errors arising from an invalid secret key.
#[derive(Clone, Copy, Debug)]
pub enum InvalidKey {
    /// The provided secret key contains an interior NUL byte.
    InteriorNul,
    /// The provided secret key is empty.
    ZeroLength,
    /// The provided secret key is longer than 256 bytes.
    TooLong,
}

/// Represents errors arising from an invalid challenge.
#[derive(Clone, Copy, Debug)]
pub enum InvalidChallenge {
    /// The provided challenge contains an interior NUL byte.
    InteriorNul,
    /// The provided challenge is longer than 64 bytes.
    TooLong,
}

impl From<InvalidKey> for Error {
    fn from(other: InvalidKey) -> Self {
        Self::InvalidKey(other)
    }
}

impl From<InvalidChallenge> for Error {
    fn from(other: InvalidChallenge) -> Self {
        Self::InvalidChallenge(other)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidKey(_) => "invalid secret key",
            Self::InvalidChallenge(_) => "invalid challenge",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::InvalidKey(e) => Some(e),
            Self::InvalidChallenge(e) => Some(e),
        }
    }
}

impl Display for InvalidKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InteriorNul => "secret key contains one or more interior NUL bytes",
            Self::ZeroLength => "secret key is empty",
            Self::TooLong => "secret key is longer than 256 bytes",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKey {}

impl Display for InvalidChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InteriorNul => "challenge contains one or more interior NUL bytes",
            Self::TooLong => "challenge is longer than 64 bytes",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidChallenge {}
