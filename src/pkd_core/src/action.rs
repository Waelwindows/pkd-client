//! PKD protocol messages
//!
//!

use crate::{utils::{sealed::Sealed, Encrypted, Timestamped}, MerkleRoot, PublicKey};


/// A hack to get around Rust not having type functions
///
/// This is a wrapper trait to allow structs to be polymorphic over container.
/// For example, [`AddOrRevokeKey<CipherText>`] indicates that some of the fields in [`AddOrRevokeKey`] are encrypted.
/// Meanwhile, [`AddOrRevokeKey<SymmetricKey>`] indicates that those fields are symmetric keys instead.
pub trait Wrap: Sealed {
    /// What to wrap T with.
    type Wrapper<T>;
}

/// Acts like identity function for [`Wrap`].
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlainText;

impl Sealed for PlainText {}
impl Wrap for PlainText {
    type Wrapper<T> = T;
}

/// Indicates the inner type is encrypted.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CipherText;

impl Sealed for CipherText {}
impl Wrap for CipherText {
    type Wrapper<T> = Encrypted<T>;
}

/// Indicate the inner type is a symmetric key
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SymmetricKey(#[serde(with = "crate::utils::serde_base64")] pub Vec<u8>);

impl Sealed for SymmetricKey {}
impl Wrap for SymmetricKey {
    type Wrapper<T> = Self;
}


/// PKD protocol messages
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action")]
pub enum Action {
    /// The [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PDK message
    AddKey {
        /// The inner content
        message: Timestamped<AddOrRevokeKey<CipherText>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: AddOrRevokeKey<SymmetricKey>,
    },
    /// The [`RevokeKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokekey) PDK message
    RevokeKey {
        /// The inner content
        message: Timestamped<AddOrRevokeKey<CipherText>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: AddOrRevokeKey<SymmetricKey>,
    },
    /// The [`RevokeKeyThirdParty`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokekeythirdparty) PDK message
    RevokeKeyThirdParty {
        /// a compact token that a user can issue at any time to revoke an existing public key
        revocation_token: RevocationToken,
    },
    /// The [`MoveIdentity`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#moveidentity) PDK message
    MoveIdentity {
        /// The ciphertext
        message: Timestamped<MoveIdentity<CipherText>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: MoveIdentity<SymmetricKey>,
    },
    /// The [`BurnDown`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#burndown) PDK message
    BurnDown {
        /// The ciphertext
        message: Timestamped<BurnDown<CipherText>>,
        /// A one-time password
        #[serde(default, skip_serializing_if = "Option::is_none")]
        otp: Option<String>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: BurnDown<SymmetricKey>,
    },
    /// The [`Fireproof`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#fireproof) PDK message
    Fireproof {
        /// The ciphertext
        message: Timestamped<Fireproof<CipherText>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: Fireproof<SymmetricKey>,
    },
    /// The [`UndoFireproof`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#undofireproof) PDK message
    UndoFireproof {
        /// The ciphertext
        message: Timestamped<Fireproof<CipherText>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: Fireproof<SymmetricKey>,
    },
    /// The [`AddAuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata) PDK message
    AddAuxData {
        /// The ciphertext
        message: Timestamped<AuxData<AddAuxDataInner<CipherText>>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: AddAuxDataInner<SymmetricKey>,
    },
    /// The [`RevokeAuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#revokeauxdata) PDK message
    RevokeAuxData {
        /// The ciphertext
        message: Timestamped<AuxData<RevokeAuxDataInner<CipherText>>>,
        /// The symmetric keys used to encrypt [`message`]
        symmetric_keys: RevokeAuxDataInner<SymmetricKey>,
    },
    /// The [`Checkpoint`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#checkpoint) PDK message
    Checkpoint {
        /// The inner content
        message: Timestamped<Checkpoint>,
    },
}

/// A concrete id for a fediverse Actor
pub type ActorId = String;

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AddOrRevokeKey<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
    /// The public key to add or revoke.
    pub public_key: M::Wrapper<PublicKey>,
}

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MoveIdentity<M: Wrap> {
    /// Who is being moved.
    pub old_actor: M::Wrapper<ActorId>,
    /// Their new Actor ID.
    pub new_actor: M::Wrapper<ActorId>,
}

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BurnDown<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
    /// The instance operator that is issuing the [`BurnDown`] on behalf of the user.
    pub operator: M::Wrapper<ActorId>,
}

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Fireproof<M: Wrap> {
    /// The canonical Actor ID for a given ActivityPub user.
    pub actor: M::Wrapper<ActorId>,
}

/// [`AuxData`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addauxdata) PKD protocol message attributes
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuxData<T> {
    aux_id: Option<String>,
    aux_type: String,
    #[serde(flatten)]
    inner: T,
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

/// [`AddKey`](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#addkey) PKD protocol message
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Checkpoint {
    /// The public URL of the PKD sending this Message
    pub from_directory: String,
    /// The Merkle root of the PKD that is signing this request.
    pub from_root: MerkleRoot,
    /// The current public key for the PKD sending the request.
    pub from_public_key: PublicKey,
    /// The public URL of the recipient PKD for this Message.
    pub to_directory: String,
    /// The latest validated Merkle root of the recipient server.
    pub to_validated_root: MerkleRoot,
}

///  a compact token that a user can issue at any time to revoke an existing public key
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RevocationToken(String);
