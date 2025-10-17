use crate::{
    action::{ActorId, CipherText, SymmetricKey, Wrap},
    utils::Timestamped,
};

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action")]
/// The [`UndoFireproof`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#undofireproof) PDK message
pub struct FireproofOrUndo {
    /// The ciphertext
    pub message: Timestamped<FireproofInner<CipherText>>,
    /// The symmetric keys used to encrypt `message`
    pub symmetric_keys: FireproofInner<SymmetricKey>,
}

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FireproofInner<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
}
