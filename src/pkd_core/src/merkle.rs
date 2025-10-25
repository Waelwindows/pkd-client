use crate::utils::{PrefixedBase64, PrefixedBase64Value};

/// A PKD v1 Merkle root
pub type MerkleRoot = PrefixedBase64<MerkleRootTag>;

/// A [`PrefixedBase64`] tag for a Merkle root tree
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, serde::Serialize)]
pub struct MerkleRootTag;

impl PrefixedBase64Value for MerkleRootTag {
    type Value = [u8; 32];
    const PREFIX: &'static str = "pkd-mr-v1";
    const LEN: usize = 32;
    const ENCODED_LEN: usize = 43;
}

#[cfg(test)]
mod tests {
    use super::MerkleRoot;

    const KEY: MerkleRoot = MerkleRoot::new([
        237, 60, 10, 1, 185, 34, 40, 32, 144, 184, 42, 67, 5, 93, 134, 110, 73, 36, 32, 55, 204,
        131, 96, 38, 27, 180, 204, 30, 165, 193, 12, 149,
    ]);
    const KEY_ENCODED: &str = "pkd-mr-v1:7TwKAbkiKCCQuCpDBV2GbkkkIDfMg2AmG7TMHqXBDJU";

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
