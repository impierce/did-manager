# DID Manager

Implementation of [identity.rs](https://github.com/iotaledger/identity.rs) interfaces for various DID methods.

## Supported DID methods

> [!NOTE]
> We refer to the [DID Core](https://www.w3.org/TR/did-core/#conformance) spec for the definition of the terms **consumer** and **producer**.

| Method                                                                                        |        Consumer         |        Producer         |
| --------------------------------------------------------------------------------------------- | :---------------------: | :---------------------: |
| [did:key](https://w3c-ccg.github.io/did-method-key/)                                          | :ballot_box_with_check: | :ballot_box_with_check: |
| [did:web](https://w3c-ccg.github.io/did-method-web/)                                          | :ballot_box_with_check: |                         |
| [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)                             | :ballot_box_with_check: |                         |
| [did:smr](https://wiki.iota.org/identity.rs/references/specifications/iota-did-method-spec/)  |                         |                         |
| [did:iota](https://wiki.iota.org/identity.rs/references/specifications/iota-did-method-spec/) |                         |                         |
