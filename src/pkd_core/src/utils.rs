use std::{fmt::Display, ops::Deref, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding};

pub(crate) mod sealed {
    /// A marker trait to indicate downstream crates shouldn't implement traits.
    pub trait Sealed {}
}

/// Encrypted ciphertext encoded in [`base64url`](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
// TODO: Handle serialize, deserialize
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Encrypted<P> {
    #[serde(with = "serde_base64")]
    ciphertext: Vec<u8>,
    #[serde(skip)]
    _tag: std::marker::PhantomData<P>,
}

impl<P> Deref for Encrypted<P> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.ciphertext
    }
}

impl<P> Encrypted<P> {
    /// Construct [`Encrypted`] from `cipher`.
    ///
    /// # Example
    /// ```
    /// let cipher = vec![0x1];
    /// let enc = Encrypted::from_ciphertext(cipher.clone())
    /// assert_eq!(enc.into_inner(), cipher)
    /// ```
    pub const fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
        Self {
            ciphertext,
            _tag: std::marker::PhantomData,
        }
    }

    /// Return the inner ciphertext
    ///
    /// # Example
    /// ```
    /// let cipher = vec![0x1];
    /// let enc = Encrypted::from_ciphertext(cipher.clone())
    /// assert_eq!(enc.into_inner(), cipher)
    /// ```
    pub fn into_inner(self) -> Vec<u8> {
        self.ciphertext
    }
}

/// A timestmap encoded in seconds since unix epoch
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    /// Get the current system [`Timestamp`]
    ///
    /// # Panics
    /// This function may panic if [`std::time::SystemTime::now`] returns a value before [`std::time::UNIX_EPOCH`].
    pub fn now() -> Self {
        let now = std::time::SystemTime::now();
        let sec = now
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time to be after unix epoch");
        Self(sec.as_secs().to_string())
    }

    /// Returns the [`Timestamp`] represnting unix epoch.
    #[allow(dead_code)]
    pub(crate) fn epoch() -> Self {
        Self("0".to_string())
    }

    /// Returns the duration of this [`Timestamp`] since unix epoch
    ///
    /// # Example
    /// ```
    /// let ts1 = Timestamp::now();
    /// std::thread::sleep(std::time::Duration::from_secs(1));
    /// let ts2 = Timestamp::now();
    /// assert!(ts2.since_epoch() >= ts1.since_epoch())
    /// ```
    pub fn since_epoch(&self) -> Option<std::time::Duration> {
        let secs: u64 = self.0.parse().ok()?;
        Some(Duration::from_secs(secs))
    }
}

/// Adds a [`Timestamp`] to the type
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Timestamped<T> {
    /// The timestamp
    pub time: Timestamp,
    /// The inner wrapped type
    #[serde(flatten)]
    pub inner: T,
}

impl<T> Timestamped<T> {
    pub const fn new(time: Timestamp, inner: T) -> Self {
        Self { time, inner }
    }

    pub fn now(inner: T) -> Self {
        Self {
            time: Timestamp::now(),
            inner,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn epoch(inner: T) -> Self {
        Self {
            time: Timestamp::epoch(),
            inner,
        }
    }
}

pub trait PrefixedBase64Value {
    type Value: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;
    const PREFIX: &'static str;
    const LEN: usize;
    const ENCODED_LEN: usize;
}

/// A [base64url](https://datatracker.ietf.org/doc/html/rfc4648#autoid-10) encoded binary value.
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone)]
pub struct PrefixedBase64<T: PrefixedBase64Value>(pub T::Value);

impl<T: PrefixedBase64Value> PrefixedBase64<T> {
    /// Create a new value of [`PrefixedBase64`]
    /// # Example
    /// ```
    /// use pkd_core::key::ed25519::Ed25519Tag;
    ///
    /// let key: [u8; 32] = [
    ///     0x4e, 0x6d, 0x97, 0x06, 0xf6, 0xf4, 0x98, 0x06, 0xf8, 0x95, 0xd5, 0x6e, 0x6c, 0x2c, 0xef,
    ///     0xcf, 0x41, 0xcc, 0x4d, 0xcc, 0xd1, 0xf1, 0x51, 0x85, 0xe3, 0x8b, 0x2f, 0xe3, 0xbf, 0x15,
    ///     0x14, 0xb3,
    /// ];
    /// let val = PrefixedBase64::<Ed25519Tag>::new(key); // key's type depends on Edd25519Tag
    /// assert_eq!(val.to_string(), "ed25519:Tm2XBvb0mAb4ldVubCzvz0HMTczR8VGF44sv478VFLM")
    /// ```
    pub const fn new(val: T::Value) -> Self {
        Self(val)
    }
}

impl<T: PrefixedBase64Value> Display for PrefixedBase64<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}:{}",
            T::PREFIX,
            Base64UrlUnpadded::encode_string(self.0.as_ref())
        ))
    }
}

impl<T: PrefixedBase64Value> From<PrefixedBase64<T>> for String {
    fn from(val: PrefixedBase64<T>) -> Self {
        val.to_string()
    }
}

impl<T: PrefixedBase64Value> serde::Serialize for PrefixedBase64<T> {
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#merkle-root-encoding
    //# Each Merkle Root will be encoded as an unpadded base64url string, prefixed with a distinct prefix for the current protocol version followed by a colon (currently, pkd-mr-v1:).
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, T: PrefixedBase64Value> serde::Deserialize<'de> for PrefixedBase64<T> {
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#merkle-root-encoding
    //# Each Merkle Root will be encoded as an unpadded base64url string, prefixed with a distinct prefix for the current protocol version followed by a colon (currently, pkd-mr-v1:).
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PrefixedVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: PrefixedBase64Value> serde::de::Visitor<'de> for PrefixedVisitor<T> {
            type Value = PrefixedBase64<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64url encoded value")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let rest = v.strip_prefix(&format!("{}:", T::PREFIX)).ok_or_else(|| {
                    E::custom(format!("expected value to start with '{}:'", T::PREFIX))
                })?;
                if rest.len() == T::ENCODED_LEN {
                    // HACK: can't use const generic parameter to make array
                    let mut key = vec![0; T::LEN];
                    let wrote = Base64UrlUnpadded::decode(rest, &mut key)
                        .map_err(|_| E::custom("failed to decode base64url"))?
                        .len();
                    if T::LEN == wrote {
                        Ok(PrefixedBase64(T::Value::try_from(&key).map_err(|_| {
                            E::custom("expected to instantiate value from bytes")
                        })?))
                    } else {
                        Err(E::custom(format!(
                            "invalid key length, expected {} found {}",
                            T::LEN,
                            wrote
                        )))
                    }
                } else {
                    Err(E::custom(format!(
                        "invalid encoded length, expected {} found {}",
                        T::ENCODED_LEN,
                        rest.len()
                    )))
                }
            }
        }

        deserializer.deserialize_str(PrefixedVisitor(std::marker::PhantomData))
    }
}

pub mod serde_base64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        // TODO: confirm whether there's padding or no
        let b64 = Base64UrlUnpadded::encode_string(bytes);
        serializer.serialize_str(&b64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Base64Visitor;

        impl<'de> serde::de::Visitor<'de> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("base64url encoded bytes")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Base64UrlUnpadded::decode_vec(v).map_err(|_| E::custom("base64url decoding error"))
            }
        }

        deserializer.deserialize_str(Base64Visitor)
    }
}

// SAFETY: We assume in good faith that [`serde`] and [`serde_json`] don't unneccessairly clone secret
pub mod serde_base64_secrecy {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use secrecy::{ExposeSecret, SecretBox};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &SecretBox<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // TODO: confirm whether there's padding or no
        let b64 = Base64UrlUnpadded::encode_string(bytes.expose_secret());
        serializer.serialize_str(&b64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretBox<Vec<u8>>, D::Error> {
        struct Base64Visitor;

        impl<'de> serde::de::Visitor<'de> for Base64Visitor {
            type Value = SecretBox<Vec<u8>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("base64url encoded bytes")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let mut ret = Ok(0);
                let secret = SecretBox::<Vec<u8>>::init_with_mut(|b| {
                    // SAFETY: We know that base64url encoding is always bigger than data
                    // Thus, we are sure we won't reallocate after this
                    b.reserve_exact(v.len());
                    ret = Base64UrlUnpadded::decode(v, b)
                        .map(|x| x.len())
                        .map_err(|_| E::custom("failed to decode base64url bytes"));
                });
                ret.map(|_| secret)
            }
        }

        deserializer.deserialize_str(Base64Visitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::Encrypted;

    #[test]
    fn encode_encrypted() {
        assert_eq!(
            serde_json::to_string(&Encrypted::<String>::from_ciphertext(vec![1, 2, 3])).unwrap(),
            "\"AQID\""
        );
    }
}
