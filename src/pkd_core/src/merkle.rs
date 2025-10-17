use base64ct::{Base64UrlUnpadded, Encoding};

/// A PKD Merkle-tree root
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleRoot {
    /// Version 1 encoding
    V1([u8; 32]),
}

impl MerkleRoot {
    const V1_LEN: usize = 32;
    const V1_ENCODED_LEN: usize = 43;
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleRoot::V1(p) => f.write_fmt(format_args!(
                "pkd-mr-v1:{}",
                Base64UrlUnpadded::encode_string(p)
            )),
        }
    }
}

impl serde::Serialize for MerkleRoot {
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#merkle-root-encoding
    //# Each Merkle Root will be encoded as an unpadded base64url string, prefixed with a distinct prefix for the current protocol version followed by a colon (currently, pkd-mr-v1:).
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{self}"))
    }
}

impl<'de> serde::Deserialize<'de> for MerkleRoot {
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#merkle-root-encoding
    //# Each Merkle Root will be encoded as an unpadded base64url string, prefixed with a distinct prefix for the current protocol version followed by a colon (currently, pkd-mr-v1:).
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MerkleRootVisitor;

        impl<'de> serde::de::Visitor<'de> for MerkleRootVisitor {
            type Value = MerkleRoot;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a PKD encoded merkle root.")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let (tag, rest) = v.split_once(':').ok_or(E::custom("expected ':'"))?;
                match tag {
                    "pkd-mr-v1" => {
                        if rest.len() == MerkleRoot::V1_ENCODED_LEN {
                            let mut key = [0; 32];
                            let wrote = Base64UrlUnpadded::decode(rest, &mut key)
                                .map_err(|_| E::custom("failed to decode base64url"))?
                                .len();
                            if MerkleRoot::V1_LEN == wrote {
                                Ok(MerkleRoot::V1(key))
                            } else {
                                Err(E::custom(format!(
                                    "invalid key length, expected {} found {}",
                                    MerkleRoot::V1_LEN,
                                    wrote
                                )))
                            }
                        } else {
                            Err(E::custom(format!(
                                "invalid encoded length, expected {} found {}",
                                MerkleRoot::V1_ENCODED_LEN,
                                rest.len()
                            )))
                        }
                    }
                    e => Err(E::custom(format!("unknown tag found: {e}"))),
                }
            }
        }

        deserializer.deserialize_str(MerkleRootVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleRoot;

    const KEY: MerkleRoot = MerkleRoot::V1([
        237, 60, 10, 1, 185, 34, 40, 32, 144, 184, 42, 67, 5, 93, 134, 110, 73, 36, 32, 55, 204,
        131, 96, 38, 27, 180, 204, 30, 165, 193, 12, 149,
    ]);
    const KEY_ENCODED: &'static str = "pkd-mr-v1:7TwKAbkiKCCQuCpDBV2GbkkkIDfMg2AmG7TMHqXBDJU";

    #[test]
    fn encode() {
        assert_eq!(format!("{KEY}"), KEY_ENCODED)
    }

    #[test]
    fn decode() {
        assert_eq!(
            serde_json::from_str::<MerkleRoot>(&format!("\"{KEY_ENCODED}\"")).unwrap(),
            KEY
        );
        assert!(serde_json::from_str::<MerkleRoot>("").is_err()); // empty key
        assert!(serde_json::from_str::<MerkleRoot>("invalid:key").is_err()); // invalid tag
        assert!(serde_json::from_str::<MerkleRoot>("ed25519:key").is_err()); // invalid encoded key size
    }
}
