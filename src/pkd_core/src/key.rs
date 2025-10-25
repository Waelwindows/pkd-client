use crate::utils::{PrefixedBase64, PrefixedBase64Value};

/// a [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) public key.
pub type PublicKey = PrefixedBase64<Ed25519Tag>;
/// A [`PrefixedBase64`] tag for a [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) public key.
#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519Tag;

impl PrefixedBase64Value for Ed25519Tag {
    type Value = [u8; 32];
    const PREFIX: &'static str = "ed25519";
    const LEN: usize = 32;
    const ENCODED_LEN: usize = 43;
}

//= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#public-key-encoding
//= type=test
#[cfg(test)]
mod tests {
    use super::PublicKey;

    const KEY: PublicKey = PublicKey::new([
        0x4e, 0x6d, 0x97, 0x06, 0xf6, 0xf4, 0x98, 0x06, 0xf8, 0x95, 0xd5, 0x6e, 0x6c, 0x2c, 0xef,
        0xcf, 0x41, 0xcc, 0x4d, 0xcc, 0xd1, 0xf1, 0x51, 0x85, 0xe3, 0x8b, 0x2f, 0xe3, 0xbf, 0x15,
        0x14, 0xb3,
    ]);
    const KEY_ENCODED: &str = "ed25519:Tm2XBvb0mAb4ldVubCzvz0HMTczR8VGF44sv478VFLM";

    #[test]
    fn encode() {
        assert_eq!(format!("{KEY}"), KEY_ENCODED)
    }

    #[test]
    fn decode() {
        assert_eq!(
            serde_json::from_str::<PublicKey>(&format!("\"{KEY_ENCODED}\"")).unwrap(),
            KEY
        );
        assert!(serde_json::from_str::<PublicKey>("").is_err()); // empty key
        assert!(serde_json::from_str::<PublicKey>("invalid:key").is_err()); // invalid tag
        assert!(serde_json::from_str::<PublicKey>("ed25519:key").is_err()); // invalid encoded key size
    }
}
