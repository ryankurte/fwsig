//! Error types for fwsig

/// Manifest error enumeration
#[derive(Copy, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ManifestError {
    #[cfg_attr(feature = "thiserror", error("Missing application checksum"))]
    MissingAppChecksum,
    #[cfg_attr(feature = "thiserror", error("Missing metadata checksum"))]
    MissingMetaChecksum,
    #[cfg_attr(feature = "thiserror", error("Invalid public key"))]
    InvalidPublicKey,
    #[cfg_attr(feature = "thiserror", error("Invalid private key"))]
    InvalidPrivateKey,
    #[cfg_attr(feature = "thiserror", error("Hex encode/decode failed"))]
    InvalidHex,
    #[cfg_attr(feature = "thiserror", error("Signing manifest failed"))]
    SigningFailed,
    #[cfg_attr(feature = "thiserror", error("No matching key for manifest verification"))]
    NoMatchingKey,
    #[cfg_attr(feature = "thiserror", error("Invalid signature"))]
    InvalidSignature,
    #[cfg_attr(feature = "thiserror", error("Signature verification failed"))]
    VerificationFailed,
}

/// Verification error enumeration
#[derive(Copy, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerifyError {
    #[cfg_attr(feature = "thiserror", error("app length mismatch"))]
    AppLengthMismatch,
    #[cfg_attr(feature = "thiserror", error("app checksum mismatch"))]
    AppChecksumMismatch,
    #[cfg_attr(feature = "thiserror", error("metadata length mismatch"))]
    MetaLengthMismatch,
    #[cfg_attr(feature = "thiserror", error("metadata checksum mismatch"))]
    MetaChecksumMismatch,
    #[cfg_attr(feature = "thiserror", error("invalid signature"))]
    InvalidSignature,
    #[cfg_attr(feature = "thiserror", error("signature verification failed"))]
    VerificationFailed,
}
