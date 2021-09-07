# **`vep`**

Variable-length Expansion Pass function. ( i.e. short password to long hashed password )


[![CI][ci-badge]][ci-url]
[![Crates.io][crates-badge]][crates-url]
[![Licensed][license-badge]][license-url]
[![Twitter][twitter-badge]][twitter-url]

[ci-badge]: https://github.com/just-do-halee/vep/actions/workflows/ci.yml/badge.svg
[crates-badge]: https://img.shields.io/crates/v/vep.svg?labelColor=383636
[license-badge]: https://img.shields.io/crates/l/vep?labelColor=383636
[twitter-badge]: https://img.shields.io/twitter/follow/do_halee?style=flat&logo=twitter&color=4a4646&labelColor=333131&label=just-do-halee

[ci-url]: https://github.com/just-do-halee/vep/actions
[twitter-url]: https://twitter.com/do_halee
[crates-url]: https://crates.io/crates/vep
[license-url]: https://github.com/just-do-halee/vep
| [Docs](https://docs.rs/vep) | [Latest Note](https://github.com/just-do-halee/vep/blob/main/CHANGELOG.md) |

```toml
[dependencies]
vep = "2.1.0"
```

or

```toml
[dependencies]
vep = { version = "2.1.0", default-features = false } # no-std
```

---

## How to

```rust
use vep::Vep;
use sha2::{Sha256, Digest}; // can be any hasher(dyn Digest from `digest` crate)

let src = b"hello vep!"; // <- 10 bytes
let expanded = Vep(Sha256::new()).expand(src); // -> 10 * 32 bytes == `320 bytes`

assert_eq!(expanded.len(), Vep::<Sha256>::output_size_calc(src));
```

## Fixed size available
```rust
let src = b"hello vep!"; // <- 10 bytes
let result = Vep(Sha256::new()).expand_and_then_reduce(src); // -> 320 bytes -> `32 bytes` (reduced)

assert_eq!(result.len(), Vep::<Sha256>::reduced_size_calc());
```
---
## * Algorithm
---
![Vep Image](https://i.ibb.co/WgTkyXF/vep2.png)