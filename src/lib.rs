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
