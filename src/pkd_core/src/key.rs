use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde;

/// A public key
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PublicKey {
    /// An [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) public key.
    Ed25519([u8; 32]),
}

impl PublicKey {
    const ED25519_LEN: usize = 32;
    const ED25519_ENCODED_LEN: usize = 43;
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        match self {
            PublicKey::Ed25519(p) => {
                f.write_fmt(format_args!("ed25519:{}", URL_SAFE_NO_PAD.encode(p)))
            }
        }
    }
}

impl serde::Serialize for PublicKey {
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#public-key-encoding
    //# Each public key will be encoded as an unpadded base64url string prefixed by the cryptography protocol name followed by a colon.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{self}"))
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#public-key-encoding
    //# Each public key will be encoded as an unpadded base64url string prefixed by the cryptography protocol name followed by a colon.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a PKD encoded public key.")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let (tag, rest) = v.split_once(':').ok_or(E::custom("expected ':'"))?;
                match tag {
                    "ed25519" => {
                        if rest.len() == PublicKey::ED25519_ENCODED_LEN {
                            let mut key = [0; 32];
                            let wrote = BASE64_URL_SAFE_NO_PAD
                                .decode_slice(rest, &mut key)
                                .map_err(|_| E::custom("failed to decode base64url key"))?;
                            if 32 == wrote {
                                Ok(PublicKey::Ed25519(key))
                            } else {
                                Err(E::custom(format!(
                                    "invalid key length, expected {} found {}",
                                    PublicKey::ED25519_LEN,
                                    wrote
                                )))
                            }
                        } else {
                            Err(E::custom(format!(
                                "invalid encoded key length, expected {} found {}",
                                PublicKey::ED25519_ENCODED_LEN,
                                rest.len()
                            )))
                        }
                    }
                    e => Err(E::custom(format!("unknown tag found: {e}"))),
                }
            }
        }

        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

//= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#public-key-encoding
//= type=test
#[cfg(test)]
mod tests {
    use super::PublicKey;

    const KEY: PublicKey = PublicKey::Ed25519([
        0x4e, 0x6d, 0x97, 0x06, 0xf6, 0xf4, 0x98, 0x06, 0xf8, 0x95, 0xd5, 0x6e, 0x6c, 0x2c, 0xef,
        0xcf, 0x41, 0xcc, 0x4d, 0xcc, 0xd1, 0xf1, 0x51, 0x85, 0xe3, 0x8b, 0x2f, 0xe3, 0xbf, 0x15,
        0x14, 0xb3,
    ]);
    const KEY_ENCODED: &'static str = "ed25519:Tm2XBvb0mAb4ldVubCzvz0HMTczR8VGF44sv478VFLM";

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
