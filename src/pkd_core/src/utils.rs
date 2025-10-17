use std::{ops::Deref, time::Duration};

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
    /// assert_eq!(enc.to_inner(), cipher)
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
    /// assert_eq!(enc.to_inner(), cipher)
    /// ```
    pub fn to_inner(self) -> Vec<u8> {
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
    pub fn now(inner: T) -> Self {
        Self {
            time: Timestamp::now(),
            inner,
        }
    }
}

pub mod serde_base64 {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        // TODO: confirm whether there's padding or no
        let b64 = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        serializer.serialize_str(&b64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base64Visitor;

        impl<'de> serde::de::Visitor<'de> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("base64url encoded bytes")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                BASE64_URL_SAFE_NO_PAD
                    .decode(v)
                    .map_err(|_| E::custom("base64url decoding error"))
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
