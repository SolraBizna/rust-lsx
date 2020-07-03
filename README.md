This is a pure, safe Rust reimplementation of [LibSolraXandria][1]. It
provides implementations of the [Twofish][2] block cipher and the
[SHA-256][3] cryptographic hash function.

Like its C99 ancestor, the library is fairly simple, runs with reasonable
speed, uses very little memory, and makes no use whatsoever of the heap
(but you are, of course, free to allocate its state objects on the heap
rather than the stack if you want to). Unlike its C99 ancestor, it is
written 100% in safe Rust code. This does not come at any cost in
performance; the Rust version and its C99 ancestor are generally neck and
neck in benchmarks.

Theoretically, `std` is not required, but this has not been tested.

[1]: https://github.com/SolraBizna/lsx
[2]: https://en.wikipedia.org/wiki/Twofish
[3]: https://en.wikipedia.org/wiki/SHA-2

Usage
-----

Add to your `Cargo.toml`, under `[dependencies]`:

```toml
lsx = "1.1"
```

Or, if you want only SHA-256 support:

```toml
lsx = {version = "1.1", default-features = false, features = ["sha256"]}
```

Or only Twofish:

```toml
lsx = {version = "1.1", default-features = false, features = ["twofish"]}
```

See the module documentation for further information. You can either [read it online][4], or set up the dependency in your `Cargo.toml` and use `cargo doc`.

[4]: https://docs.rs/lsx

License
-------

This library is distributed under the zlib license. This puts very few
restrictions on use. See [`LICENSE.md`][5] for the complete, very short text of
the license.

[5]: LICENSE.md
