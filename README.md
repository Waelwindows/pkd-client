# Fediverse Public Key Directory Client API Implementation

This is an implementation of the client-side component of the
[Public Key Directory specification](https://github.com/fedi-e2ee/public-key-directory-specification), written in Rust.
See [`fedi-e2ee/pkd-server-go`](https://github.com/fedi-e2ee/pkd-server-go) for the reference implementation of the server-side component written in Go.

## What is this, and why does it exist?

The hardest part of designing end-to-end encryption for the Fediverse, as with most cryptography undertakings, is key
management. In short: How do you know which public key belongs to a stranger you want to chat with privately? And how
do you know you weren't deceived?

Our solution is to use **Key Transparency**, which involves publishing all public key enrollments and revocations to an
append-only ledger based on Merkle trees. This allows for a verifiable, auditable log of all key-related events,
providing a strong foundation for trust.

This project, and the accompanying specification, are the result of an open-source effort to solve this problem.
You can read more about the project's origins and design philosophy on Soatok's blog, *Dhole Moments*:

* [Towards Federated Key Transparency](https://soatok.blog/2024/06/06/towards-federated-key-transparency/)
* [Key Transparency and the Right to be Forgotten](https://soatok.blog/2024/11/21/key-transparency-and-the-right-to-be-forgotten/)

## Language Bindings (FFI)
The goal of this library is to expose PKD functionality to the languages implementing fediverse software.
The plan is to use the [`uniffi`](https://github.com/mozilla/uniffi-rs) crate to expose bindings to the following according to https://github.com/fedi-e2ee/public-key-directory-specification/issues/78
1. TypeScript - Misskey, PeerTube, Micro.blog, etc. (Also for browser extensions)
2. Ruby - Mastodon (and its many forks), etc.
3. Python - Bridgy, Bookworm
4. Go - WriteFreely

Furthermore, we can expose Dart, Kotlin and Swift for mobile clients as well.

This leaves the following languages to implement bindings for
1. PHP - Pixelfed, Friendica, etc.
2. Elixir - Pleroma, Mobilizon, Akkoma, etc.

## License

This project is licensed under the [MIT License](LICENSE).
