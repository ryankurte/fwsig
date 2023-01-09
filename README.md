# fwsig, simple firmware signing and verification

`fwsig` provides a simple specification for firmware manifests supporting firmware signing and verification, along with tooling for signing and verifying these manifests and packaging firmware into signed objects, and librar(y|ies) for parsing and using these manifests.


## Status

stability is not _yet_ guaranteed as the initial specification is pending review / real-world use. if you have issues / suggestions / needs this does not fulfill please open an issue!

[![ci](https://github.com/ryankurte/fwsig/actions/workflows/ci.yml/badge.svg)](https://github.com/ryankurte/fwsig/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/fwsig.svg)](https://crates.io/crates/fwsig)
[![Docs.rs](https://docs.rs/fwsig/badge.svg)](https://docs.rs/fwsig)


## Usage

### Signing Firmware

TODO

### Using `fwsig`

TODO


## Design

`fwsig` provides a simple constant-length manifest describing an application along with (optional) associated metadata and the public key of the signing keypair, with a signature over the entire object.

Metadata support allows applications to be packaged with relevant meta-information for loading and execution, for example application names and versions, supported devices, and device configurations.
Due to disparate application needs, metadata encoding is not specified, though helpers may be provided for specific formats (such as JSON or CBOR).

For implementation details, please see the rust [reference implementation](https://docs.rs/fwsig).


### Packaging Applications

Applications are typically packaged by first generating and signing a manifest, then concatenating the binary firmware, metadata, and manifest object (though these components _may_ be distributed separately if required).

```text
  ┌───────────────────────────────────────────────┐
  │ Application                                   │
  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   │
  │  │ Firmware │ + │ Metadata │ + │ Manifest │   │
  │  └──────────┘   └──────────┘   └──────────┘   │
  └───────────────────────────────────────────────┘
```

To load an application package one first parses the manifest using the constant length as an offset from the end of the file, ensuring the signature is valid over the manifest object, verifies the signing key[^1], then uses the lengths and checksums from the manifest to load the firmware and metadata components


[^1]: production firmware _should_ contain a list of trusted keys, along with a mechanism to trust a user key to enable safe end-user customisation. Development firmware may also allow untrusted transient keys.


### The Manifest Format

The Manifest is a 212-byte constant-length little-endian object including the manifest information, application name ane version strings, lengths and checksums for both the application and metadata, and the signing key and signature.

See the [docs](https://docs.rs/fwsig/latest/fwsig/struct.Manifest.html) for a detailed layout.

To simplify parsing manifest objects are _always_ signed. If trusted keys are not provided a temporary key is generated for the signing operation and the `TRANSIENT_KEY` flag is set.


