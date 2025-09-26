# DID Manager

[![semantic-release: angular](https://img.shields.io/badge/semantic--release-angular-e10079?logo=semantic-release)](https://github.com/semantic-release/semantic-release)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/impierce/did-manager/badge)](https://scorecard.dev/viewer/?uri=github.com/impierce/did-manager)
[![Coveralls](https://coveralls.io/repos/github/impierce/did-manager/badge.svg?branch=beta)](https://coveralls.io/github/impierce/did-manager?branch=beta)

---

Implementation of [identity.rs](https://github.com/iotaledger/identity.rs) interfaces for various DID methods.

## Supported DID methods

> [!NOTE]
> We refer to the [DID Core](https://www.w3.org/TR/did-core/#conformance) spec for the definition of the terms **consumer** and **producer**. "Consuming" means resolving and verifying, while "producing" means creating a DID document from given key material.

| Method                                                                                        |        Consumer         |        Producer         |
| --------------------------------------------------------------------------------------------- | :---------------------: | :---------------------: |
| [did:key](https://w3c-ccg.github.io/did-method-key/)                                          | :ballot_box_with_check: | :ballot_box_with_check: |
| [did:web](https://w3c-ccg.github.io/did-method-web/)                                          | :ballot_box_with_check: | :ballot_box_with_check: |
| [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)                             | :ballot_box_with_check: | :ballot_box_with_check: |
| [did:iota](https://wiki.iota.org/identity.rs/references/specifications/iota-did-method-spec/) | :ballot_box_with_check: |                         |

## Usage

> [!NOTE]
> This workspace is structured in a way that keeps the individual DID method implementations as separate crates to allow easier replacement and extensibility.

### Consuming DIDs

```rust
use did_manager::Resolver;
use identity_iota::document::CoreDocument;

let resolver = Resolver::new().await;
let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
let document: CoreDocument = resolver.resolve(did).await.unwrap();
```

### Producing DIDs

```rust
use did_manager::{DidMethod, SecretManager};
use identity_iota::document::CoreDocument;

let secret_manager = SecretManager::builder()
            .snapshot_path("/path/to/file.stronghold")
            .password("p4ssw0rd")
            .build()
            .await
            .unwrap();

let document: CoreDocument = secret_manager.produce_document(DidMethod::Jwk).await.unwrap();
```

## Development

### Test coverage

To generate a test coverage report locally, run the following command:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Create a test coverage report
cargo tarpaulin --workspace --out html --output-dir target/coverage
```
