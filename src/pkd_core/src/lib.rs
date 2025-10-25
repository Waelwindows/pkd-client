//! Core API definitions `pkd`
//!
//! This crate contains all the core API for PKD functionality without IO.
//! For IO, you should look at `pkd_client`

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod action;
mod key;
mod merkle;
mod utils;

pub use key::*;
pub use merkle::*;
pub use utils::PrefixedBase64;
