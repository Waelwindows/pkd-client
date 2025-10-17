//! Core API definitions `pkd`
//!
//! This crate contains all the core API for PKD functionality without IO.
//! For IO, you should look at [`pkd_client`]

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod key;

pub use key::*;
