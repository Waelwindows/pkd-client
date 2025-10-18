use crate::{
    PublicKey,
    action::{ActorId, CipherText, SymmetricKey, Wrap},
    utils::Timestamped,
};

/// The [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PDK message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AddOrRevokeKey {
    /// The inner content
    pub message: Timestamped<AddOrRevokeKeyInner<CipherText>>,
    /// The symmetric keys used to encrypt `message`
    pub symmetric_keys: AddOrRevokeKeyInner<SymmetricKey>,
}

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AddOrRevokeKeyInner<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
    /// The public key to add or revoke.
    pub public_key: M::Wrapper<PublicKey>,
}
