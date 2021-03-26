# gs-secure-validate

![GitHub Actions](https://github.com/FaultyRAM/gs-secure-validate/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/gs-secure-validate.svg)](https://crates.io/crates/gs-secure-validate)
[![Docs.rs](https://docs.rs/gs-secure-validate/badge.svg)](https://docs.rs/gs-secure-validate)

Generates responses to a GameSpy protocol secure/validate challenge.

## Usage

Add gs-secure-validate to your `Cargo.toml`:

```toml
[dependencies]
gs-secure-validate = "^1.0.0"
```

Optionally, you can enable features that require libstd (such as `Error` trait impls):

```toml
[dependencies]
gs-secure-validate = { version = "^1.0.0", features = ["std"] }
```

For more details, see the [API documentation](https://docs.rs/gs-secure-validate).

## License

Licensed under either of

* Apache License, Version 2.0,
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
