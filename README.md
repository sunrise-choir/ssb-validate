# ssb-validate

[![Build Status](https://travis-ci.org/sunrise-choir/ssb-validate.svg?branch=master)](https://travis-ci.org/github/sunrise-choir/ssb-validate) ![Version badge](https://img.shields.io/badge/version-1.4.0-blue.svg) [![Documentation badge](https://img.shields.io/badge/rust-docs-blue)](https://sunrise-choir.github.io/ssb-validate/ssb_validate/index.html)

Validate Secure Scuttlebutt (SSB) message and message values, either individually or as hash chains (with support for parallel batch validation).

The aim here is to get as close as possible to the full set of validation criteria employed by the [JavaScript implementation of ssb-validate](https://github.com/ssb-js/ssb-validate).

Support for out-of-order validation (regular and parallel) and multi-author out-of-order validation (regular and parallel) has been added.

## Usage

Visit the [ssb-validate2-rsjs-node](https://github.com/ssb-ngi-pointer/ssb-validate2-rsjs-node) repo (the `src/lib.rs` file in particular) to see examples of this crate in action. The validation functionality is paired with [ssb-verify-signatures](https://github.com/sunrise-choir/ssb-verify-signatures) to perform complete validation of SSB messages. A technique for returning an invalid message when performing parallel validation is also included in the code.

Further examples can be seen in the tests of `src/message.rs` and `src/message_value.rs` in this repo.

## Validation Critera

Secure Scuttlebutt "feeds" are a sequence of messages published by one author. To be valid, a message must satisfy a number of criteria. The exact criteria depend on the context of the message. It's important to note that this crate does not perform signature verification. See the [ssb-verify-signatures](https://github.com/sunrise-choir/ssb-verify-signatures) repo for that functionality.

If the message is the first in the feed:

 - the value of the `previous` field must be `null`
 - the value of the `sequence` field must be `1`

If the message is not the first in the feed:

 - the value of the `previous` field must be the hash of the previous message
 - the value of the `sequence` field must be 1 larger than the `sequence` of the previous message

Other criteria which all messages must satisfy (unless they are being validated out-of-order):

 - the value of the `hash` field must be `sha256`
 - the `author` must not change compared to the previous message
 - if the message includes a `key`, it must be the hash of the `value` of the message
 - message `value` fields must be in the order: `previous`, `author` or `sequence`, `author` or `sequence`, `timestamp`, `hash`, `content`, `signature`
 - the message `value` must not include extra (unexpected) fields
 - the value of the message `content` field must be encoded in canonical base64 and contain `.box` if it is a string (encrypted private message)
 - the length of the serialized message `value` must not exceed 8192 UTF-16 code units

All of the above criteria are validated by this library (either directly or via dependencies).

You can check messages one by one or batch process a collection of them (uses [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html) internally)

In addition to validating messages using all of the above criteria, it is also possible to validate out-of-order messages by satifying a subset of those criteria. This crate provides functions to perform batch validation of such out-of-order messages.

Out-of-order message validation may be performed for single-author or multi-author use-cases (separate functions exist for each case).

When performing validation for out-of-order messages from a single author, the messages must be authored by a single keypair. However, it is not required that the sequence number of a message be 1 larger than the sequence number of the previous message, nor is it required that the hash of the previous message match the hash given for the previous message in a message.

Multi-author validation, by contrast to the above, does not perform any checks of the `previous` message. Indeed, it may be said that this method of validation has no concept of a previous message (except that the `previous` field must be present in the message in the correct order).

## Useful Documentation

 - [User-guide for Sunrise Choir crates](https://dev.scuttlebutt.nz/#/rust/sunrise-choir): should be useful for application developers
 - [Specification for data type, data model, feed and messages](https://spec.scuttlebutt.nz/): detailed information for developers working at the protocol level
 - [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/index.html): excellent overview of the SSB protocol (required reading)

The doc comments for this crate and all dependencies can be built and served locally by cloning the repo and running `cargo doc --open`. You can find more information about `cargo doc` [here](https://doc.rust-lang.org/cargo/commands/cargo-doc.html).

## License

AGPL-3.0
