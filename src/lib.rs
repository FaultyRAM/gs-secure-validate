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
#![allow(clippy::must_use_candidate)]

#[cfg(not(feature = "std"))]
use core as std_crate;
#[cfg(feature = "std")]
use std as std_crate;

#[cfg(feature = "std")]
use std_crate::error;
use std_crate::{
    borrow::Borrow,
    fmt::{self, Display, Formatter},
    ops::Deref,
    str,
};

macro_rules! swap {
    ($a:expr, $b:expr) => {
        #[allow(clippy::manual_swap)]
        {
            let t = $a;
            $a = $b;
            $b = t;
        }
    };
}

/// The generated response to a secure/validate challenge.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    buffer: [u8; 88],
    len: usize,
}

/// Represents errors arising from this crate.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// The provided secret key is invalid.
    InvalidKey(KeyError),
    /// The provided challenge is invalid.
    InvalidChallenge(ChallengeError),
}

/// Represents errors arising from an invalid secret key.
#[derive(Clone, Copy, Debug)]
pub enum KeyError {
    /// The provided secret key contains an interior NUL byte.
    InteriorNul,
    /// The provided secret key is empty.
    ZeroLength,
    /// The provided secret key is longer than 256 bytes.
    TooLong,
}

/// Represents errors arising from an invalid challenge.
#[derive(Clone, Copy, Debug)]
pub enum ChallengeError {
    /// The provided challenge contains an interior NUL byte.
    InteriorNul,
    /// The provided challenge is longer than 64 bytes.
    TooLong,
}

impl Output {
    /// Generates a secure/validate response from a secret key and challenge.
    ///
    /// # Errors
    ///
    /// This function returns an `Error` if the secret key or challenge are invalid:
    ///
    /// * `Error::InvalidKey` if the secret key is invalid; the inner `KeyError` specifies the
    ///   exact problem
    /// * `Error::InvalidChallenge` if the challenge is invalid; the inner `ChallengeError`
    ///   specifies the exact problem
    pub const fn generate(secret_key: &[u8], challenge: &[u8]) -> Result<Self, Error> {
        #[inline]
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

        if secret_key.is_empty() {
            Err(Error::InvalidKey(KeyError::ZeroLength))
        } else if secret_key.len() > 256 {
            Err(Error::InvalidKey(KeyError::TooLong))
        } else if has_interior_nul(secret_key) {
            Err(Error::InvalidKey(KeyError::InteriorNul))
        } else if challenge.len() > 64 {
            Err(Error::InvalidChallenge(ChallengeError::TooLong))
        } else if has_interior_nul(challenge) {
            Err(Error::InvalidChallenge(ChallengeError::InteriorNul))
        } else {
            let mut tmp = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
                65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
                86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104,
                105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
                121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
                137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
                153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168,
                169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
                185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200,
                201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
                217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
                233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248,
                249, 250, 251, 252, 253, 254, 255,
            ];
            let mut loop_index = 0;
            let mut x = 0;
            while loop_index < tmp.len() {
                x = secret_key[loop_index % secret_key.len()]
                    .wrapping_add(tmp[loop_index])
                    .wrapping_add(x);
                swap!(tmp[loop_index], tmp[x as usize]);
                loop_index += 1;
            }
            loop_index = 0;
            x = 0;
            let mut y = 0;
            let mut state_buffer = [0; 66];
            while loop_index < challenge.len() {
                x = challenge[loop_index].wrapping_add(x).wrapping_add(1);
                let xu = x as usize;
                y = tmp[xu].wrapping_add(y);
                let yu = y as usize;
                swap!(tmp[xu], tmp[yu]);
                let j = (tmp[xu].wrapping_add(tmp[yu])) as usize;
                state_buffer[loop_index] = challenge[loop_index] ^ tmp[j];
                loop_index += 1;
            }
            let num_src_buffers = (challenge.len() / 3) + ((challenge.len() % 3 > 0) as usize);
            let mut output = Self {
                buffer: [0; 88],
                len: num_src_buffers * 4,
            };
            loop_index = 0;
            while loop_index < num_src_buffers {
                const ENCODE_TABLE: [u8; 64] = [
                    b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M',
                    b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',
                    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm',
                    b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
                    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'+', b'/',
                ];
                let a = loop_index * 3;
                let b = loop_index * 4;
                output.buffer[b] = ENCODE_TABLE[(state_buffer[a] >> 2) as usize];
                output.buffer[b + 1] = ENCODE_TABLE
                    [(((state_buffer[a] & 0b11) << 4) | (state_buffer[a + 1] >> 4)) as usize];
                output.buffer[b + 2] = ENCODE_TABLE
                    [(((state_buffer[a + 1] & 0b1111) << 2) | (state_buffer[a + 2] >> 6)) as usize];
                output.buffer[b + 3] = ENCODE_TABLE[(state_buffer[a + 2] & 0b11_1111) as usize];
                loop_index += 1;
            }
            Ok(output)
        }
    }

    /// Returns the generated response as a string slice.
    pub fn as_str(&self) -> &str {
        // SAFETY: guaranteed to be a valid ASCII string. See `ENCODE_TABLE` above.
        unsafe { str::from_utf8_unchecked(self.as_bytes()) }
    }

    /// Returns the generated response as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<str> for Output {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<[u8]> for Output {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<str> for Output {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Deref for Output {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for Output {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<KeyError> for Error {
    fn from(other: KeyError) -> Self {
        Self::InvalidKey(other)
    }
}

impl From<ChallengeError> for Error {
    fn from(other: ChallengeError) -> Self {
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

impl Display for KeyError {
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
impl error::Error for KeyError {}

impl Display for ChallengeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InteriorNul => "challenge contains one or more interior NUL bytes",
            Self::TooLong => "challenge is longer than 64 bytes",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl error::Error for ChallengeError {}
