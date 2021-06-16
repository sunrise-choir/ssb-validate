//! Validate Secure Scuttlebutt (SSB) messages and message values, either individually or as hash chains
//! (with support for parallel batch validation).
//!
//! ## Validation Criteria
//!
//! Secure Scuttlebutt "feeds" are a sequence of messages published by one author. To be valid, a
//! message must satisfy a number of critera. The exact criteria depend on the context of the
//! message. It's important to note that this crate does not perform signature verification. See
//! the [ssb-verify-signatures](https://github.com/sunrise-choir/ssb-verify-signatures) repo for
//! that functionality.
//!
//! If the message is the first in the feed:
//!
//! - the value of the `previous` field must be `null`
//! - the value of the `sequence` field must be `1`
//!
//! If the message is not the first in the feed:
//!
//! - the value of the `previous` field must be the hash of the previous message
//! - the value of the `sequence` field must be 1 larger than the `sequence` of the previous
//! message
//!
//! Other criteria which all messages must satisfy (unless they are being validated out-of-order):
//!
//! - the value of the `hash` field must be `sha256`
//! - the `author` must not change compared the the previous message
//! - if the message includes a `key`, it must be the hash of the `value` of the message
//! - message `value` fields must be in the order: `previous`, `author` or `sequence`, `author` or
//! `sequence`, `timestamp`, `hash`, `content`, `signature`
//! - the message `value` must not include extra (unexpected) fields
//! - the value of the message `content` field must be encoded in canonical base64 and contain
//! `.box` if it is a string (encrypted private message)
//! - the length of the serialized message `value` must not exceed 8192 UTF-16 code units
//!
//! All of the above criteria are validated by this library (either directly or via dependencies).
//!
//! You can check messages one by one or batch process a collection of them (uses
//! [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html) internally)
//!
//! ## Out-of-Order (OOO) and Multi-Author Validation
//!
//! In addition to validating messages using all of the above criteria, it is also possible to
//! validate out-of-order messages or message values by satisfying a subset of those criteria. This
//! crate provides functions to perform batch validation of such out-of-order messages.
//!
//! Out-of-order message validation may be performed for single-author or multi-author use cases
//! (separate functions exist for each case).
//!
//! When performing validation for out-of-order messages from a single author, the messages must be
//! authored by a single keypair. However, it is not required that the sequence number of a message
//! be 1 larger than the sequence number of the previous message, nor is it required that the hash
//! of the previous message match the hash given for the previous message in a message.
//!
//! Multi-author validation, by contrast to the above, does not perform any checks of
//! the `previous` message. Indeed, it may be said that this method of validation has no concept of
//! a previous message (except that the `previous` field must be present in the message in the
//! correct order).
//!
//! ## Benchmarks
//!
//! Benchmarking on a 2016 2 core i5 shows that batch processing  is ~1.6 times faster than processing
//! one at a time.
//!
//! Benchmarking on Android on a [One Plus 5T](https://en.wikipedia.org/wiki/OnePlus_5T) (8 core arm64)
//! shows that batch processing is ~3.3 times faster.
pub mod error;
pub mod message;
pub mod message_value;
pub mod test_data;
pub mod utils;
