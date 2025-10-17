use crate::{
    action::{ActorId, CipherText, SymmetricKey, Wrap},
    utils::Timestamped,
};

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action")]
/// The [`AddAuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata) PDK message
pub struct AddAuxData {
    /// The ciphertext
    pub message: Timestamped<AuxData<AddAuxDataInner<CipherText>>>,
    /// The symmetric keys used to encrypt [`message`]
    pub symmetric_keys: AddAuxDataInner<SymmetricKey>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action")]
/// The [`RevokeAuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokeauxdata) PDK message
pub struct RevokeAuxData {
    /// The ciphertext
    pub message: Timestamped<AuxData<RevokeAuxDataInner<CipherText>>>,
    /// The symmetric keys used to encrypt [`message`]
    pub symmetric_keys: RevokeAuxDataInner<SymmetricKey>,
}

/// [`AuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata) PKD protocol message attributes
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuxData<T> {
    /// The identifier used by the Auxiliary Data extension.
    pub aux_type: String,
    /// An [Auxiliary Data Identifier](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#auxiliary-data-identifiers).
    ///
    /// If provided, the server will validate that the aux-id is valid for the given type and data.
    pub aux_id: Option<String>,
    /// The inner data
    #[serde(flatten)]
    pub inner: T,
}

/// [`AddAuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata) PKD protocol message attributes
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(bound(
    serialize = "M::Wrapper<Vec<u8>>: serde::Serialize, M::Wrapper<ActorId>: serde::Serialize",
    deserialize = "M::Wrapper<Vec<u8>>: serde::Deserialize<'de>, M::Wrapper<ActorId>: serde::Deserialize<'de>"
))]
pub struct AddAuxDataInner<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
    /// The auxiliary data.
    pub aux_data: M::Wrapper<Vec<u8>>,
}

/// [`RevokeAuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokeauxdata) PKD protocol message attributes
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(bound(
    serialize = "M::Wrapper<Vec<u8>>: serde::Serialize, M::Wrapper<ActorId>: serde::Serialize",
    deserialize = "M::Wrapper<Vec<u8>>: serde::Deserialize<'de>, M::Wrapper<ActorId>: serde::Deserialize<'de>"
))]
pub struct RevokeAuxDataInner<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
    /// The auxiliary data.
    pub aux_data: Option<M::Wrapper<Vec<u8>>>,
}
