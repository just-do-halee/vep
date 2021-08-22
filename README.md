# vep

Variable-length Expansion Pass function. ( i.e. short password to long hashed password )

(no dependencies, 22 lines pure safe codes, also supported no-std)  

[![Crates.io][crates-badge]][crates-url]
[![Licensed][license-badge]][license-url]
[![Twitter][twitter-badge]][twitter-url]

[crates-badge]: https://img.shields.io/crates/v/vep.svg?labelColor=383636
[twitter-badge]: https://img.shields.io/twitter/follow/do_halee?style=flat&logo=twitter&color=4a4646&labelColor=333131&label=just-do-halee

[twitter-url]: https://twitter.com/do_halee
[crates-url]: https://crates.io/crates/vep
[license-badge]: https://img.shields.io/crates/l/vep?labelColor=383636
[license-url]: https://github.com/just-do-halee/vep
| [Docs](https://docs.rs/vep) | [Latest Note](https://github.com/just-do-halee/vep/blob/main/CHANGELOG.md) |

```toml
[dependencies]
vep = "0.1.0"
```

or

```toml
[dependencies]
vep = { version = "0.1.0", features = ["std"] }
```

## How to

```rust
use sha2::Sha256; // can be any hasher

impl vep::Digester for Sha256 {
    fn digest(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.update(bytes);
        self.finalize_reset().to_vec()
    }
}


let src = b"hello vep!"; // <- 10 bytes
let expanded = Vep(Sha256::new()).expand(src); // -> 10 * 32 bytes == 320 bytes
```