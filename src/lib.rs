//! Verify Secure Scuttlebutt (SSB) hash chains (in parallel)
//!
//! Secure Scuttlebutt "feeds" are a sequence of messages published by one author.
//! To be a valid message,
//! - each message must include the hash of the preceding message
//! - the sequence number must be one larger than sequence of the preceding message
//! - the author must not change compared to the preceding message
//! - If it's the first message in a feed, the sequence must be 1 and the previous must be null.
//! - If the message includes the key, it must be that hash of the value of the message..
//!
//! You can check messages one by one or batch process a collection of them (uses [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html) internally)
//!
//! ## Benchmarks
//!
//! Benchmarking on a 2016 2 core i5 shows that batch processing  is ~1.6 times faster than processing one at a time.
//!
//! Benchmarking on Android on a [One Plus 5T](https://en.wikipedia.org/wiki/OnePlus_5T) (8 core arm64) shows that batch processing is ~3.3 times faster.
//!
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use ssb_legacy_msg_data::json::{from_slice, to_vec, DecodeJsonError, EncodeJsonError};
use ssb_legacy_msg_data::value::Value;
use ssb_legacy_msg_data::LegacyF64;
use ssb_multiformats::multihash::Multihash;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Previous message was invalid. Decoding failed with: {}", source))]
    InvalidPreviousMessage {
        source: DecodeJsonError,
        message: Vec<u8>,
    },
    #[snafu(display("Message was invalid. Decoding failed with: {}", source))]
    InvalidMessage {
        source: DecodeJsonError,
        message: Vec<u8>,
    },
    #[snafu(display(
        "Message was invalid. The authors did not match. \nAuthor of previous: {}\n Author: {} ",
        previous_author,
        author
    ))]
    AuthorsDidNotMatch {
        previous_author: String,
        author: String,
    },
    #[snafu(display("The first message of a feed must have seq of 1",))]
    FirstMessageDidNotHaveSequenceOfOne { message: Vec<u8> },
    #[snafu(display("The first message of a feed must have previous of null",))]
    FirstMessageDidNotHavePreviousOfNull { message: Vec<u8> },
    #[snafu(display("The sequence must increase by one",))]
    InvalidSequenceNumber {
        message: Vec<u8>,
        actual: u64,
        expected: u64,
    },
    #[snafu(display("Unable to get the value from the message, the message was invalid"))]
    InvalidMessageNoValue,
    #[snafu(display("Could not serialize message.value to bytes. Failed with: {}", source))]
    InvalidMessageCouldNotSerializeValue { source: EncodeJsonError },
    #[snafu(display("The actual hash of the value did not match the hash claimed by `key`"))]
    ActualHashDidNotMatchKey {
        message: Vec<u8>,
        actual_hash: Multihash,
        expected_hash: Multihash,
    },
    #[snafu(display("Previous was set to null but it should have had a value"))]
    PreviousWasNull,
    #[snafu(display(
        "This feed is forked. Last known good message was as seq: {}",
        previous_seq
    ))]
    ForkedFeed { previous_seq: u64 },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Serialize, Deserialize, Debug)]
struct SsbMessageValue {
    previous: Option<Multihash>,
    author: String,
    sequence: u64,
    timestamp: LegacyF64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SsbMessage {
    key: Multihash,
    value: SsbMessageValue,
}

/// Check that an out-of-order message is valid.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
///
/// This checks that:
/// - the author has not changed
/// - the _actual_ hash matches the hash claimed in `key`
/// - the message contains the correct fields
///
/// This does not check:
/// - the signature. See ssb-verify-signatures which lets you to batch verification of signatures.
/// - the sequence increments by 1 compared to previous
/// - the _actual_ hash of the previous message matches the hash claimed in `previous`
///
/// `previous_msg_bytes` will be `None` only when `message_bytes` is the first message by that author.

pub fn validate_ooo_message_hash_chain<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    message_bytes: T,
    previous_msg_bytes: Option<U>,
) -> Result<()> {
    let message_bytes = message_bytes.as_ref();

    let (previous_value, _previous_key) = match previous_msg_bytes {
        Some(message) => {
            let previous =
                from_slice::<SsbMessage>(message.as_ref()).context(InvalidPreviousMessage {
                    message: message.as_ref().to_owned(),
                })?;
            (Some(previous.value), Some(previous.key))
        }
        None => (None, None),
    };

    let message = from_slice::<SsbMessage>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    let message_value = message.value;

    if let Some(previous_value) = previous_value.as_ref() {
        // The authors are not allowed to change in a feed.
        ensure!(
            message_value.author == previous_value.author,
            AuthorsDidNotMatch {
                previous_author: previous_value.author.clone(),
                author: message_value.author
            }
        );
    }

    let verifiable_msg: Value = from_slice(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    // Get the value from the message as this is what was hashed
    let verifiable_msg_value = match verifiable_msg {
        Value::Object(ref o) => o.get("value").context(InvalidMessageNoValue)?,
        _ => panic!(),
    };

    // Get the "value" from the message as bytes that we can hash.
    let value_bytes =
        to_vec(verifiable_msg_value, false).context(InvalidMessageCouldNotSerializeValue)?;

    let message_actual_multihash = multihash_from_bytes(&value_bytes);

    // The hash of the "value" must match the claimed value stored in the "key"
    ensure!(
        message_actual_multihash == message.key,
        ActualHashDidNotMatchKey {
            message: message_bytes.to_owned(),
            actual_hash: message_actual_multihash,
            expected_hash: message.key,
        }
    );

    Ok(())
}

/// Batch validates a collection of out-of-order messages by a single author. Checks of previous
/// message hash and ascending sequence number are not performed, meaning that missing
/// messages are allowed and the collection is not expected to be ordered by ascending sequence
/// number.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`

pub fn par_validate_ooo_message_hash_chain_of_feed<T: AsRef<[u8]>>(messages: &[T]) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
{
    messages
        .par_iter()
        .enumerate()
        .try_fold(
            || (),
            |_, (idx, msg)| {
                if idx == 0 {
                    validate_ooo_message_hash_chain::<_, &[u8]>(msg.as_ref(), None)
                } else {
                    validate_ooo_message_hash_chain(msg.as_ref(), Some(messages[idx - 1].as_ref()))
                }
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

/// Batch validates a collection of messages, **all by the same author, ordered by ascending sequence
/// number, with no missing messages**.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
///
/// This will mainly be useful during replication. Collect all the latest messages from a feed you're
/// replicating and batch validate all the messages at once.
///
/// # Example
///```
///use ssb_validate::par_validate_message_hash_chain_of_feed;
///let valid_message_1 = r##"{
///  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
///  "value": {
///    "previous": null,
///    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "sequence": 1,
///    "timestamp": 1470186877575,
///    "hash": "sha256",
///    "content": {
///      "type": "about",
///      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///      "name": "Piet"
///    },
///    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
///  },
///  "timestamp": 1571140551481
///}"##;
///let valid_message_2 = r##"{
///  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
///  "value": {
///    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
///    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "sequence": 2,
///    "timestamp": 1470187292812,
///    "hash": "sha256",
///    "content": {
///      "type": "about",
///      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///      "image": {
///        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
///        "size": 642763,
///        "type": "image/png",
///        "width": 512,
///        "height": 512
///      }
///    },
///    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
///  },
///  "timestamp": 1571140551485
///}"##;
/// let messages = [valid_message_1.as_bytes(), valid_message_2.as_bytes()];
/// // If you're passing `None` as the `previous` argument you'll need to give the compiler a hint about
/// // the type.
/// let result = par_validate_message_hash_chain_of_feed::<_, &[u8]>(&messages, None);
/// assert!(result.is_ok());
///```

pub fn par_validate_message_hash_chain_of_feed<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    messages: &[T],
    previous: Option<U>,
) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
    U: Sync + Send + Copy,
{
    messages
        .par_iter()
        .enumerate()
        .try_fold(
            || (),
            |_, (idx, msg)| {
                if idx == 0 {
                    let prev = match previous {
                        Some(prev) => Some(prev.as_ref().to_owned()),
                        _ => None,
                    };
                    validate_message_hash_chain(msg.as_ref(), prev)
                } else {
                    validate_message_hash_chain(msg.as_ref(), Some(messages[idx - 1].as_ref()))
                }
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

/// Batch validates a collection of message values, **all by the same author, ordered by ascending sequence
/// number, with no missing messages**.
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
///
/// This will mainly be useful during replication. Collect all the latest messages from a feed you're
/// replicating and batch validate all the messages at once.
///
/// # Example
///```
///use ssb_validate::par_validate_message_value_hash_chain_of_feed;
///let valid_message_1 = r##"{
///  "previous": null,
///  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///  "sequence": 1,
///  "timestamp": 1470186877575,
///  "hash": "sha256",
///  "content": {
///    "type": "about",
///    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "name": "Piet"
///  },
///  "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
///}"##;
///let valid_message_2 = r##"{
///  "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
///  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///  "sequence": 2,
///  "timestamp": 1470187292812,
///  "hash": "sha256",
///  "content": {
///    "type": "about",
///    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "image": {
///      "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
///      "size": 642763,
///      "type": "image/png",
///      "width": 512,
///      "height": 512
///    }
///  },
///  "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
///}"##;
/// let messages = [valid_message_1.as_bytes(), valid_message_2.as_bytes()];
/// // If you're passing `None` as the `previous` argument you'll need to give the compiler a hint about
/// // the type.
/// let result = par_validate_message_value_hash_chain_of_feed::<_, &[u8]>(&messages, None);
/// assert!(result.is_ok());
///```

pub fn par_validate_message_value_hash_chain_of_feed<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    messages: &[T],
    previous: Option<U>,
) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
    U: Sync + Send + Copy,
{
    messages
        .par_iter()
        .enumerate()
        .try_fold(
            || (),
            |_, (idx, msg)| {
                if idx == 0 {
                    let prev = match previous {
                        Some(prev) => Some(prev.as_ref().to_owned()),
                        _ => None,
                    };
                    validate_message_value_hash_chain(msg.as_ref(), prev)
                } else {
                    validate_message_value_hash_chain(
                        msg.as_ref(),
                        Some(messages[idx - 1].as_ref()),
                    )
                }
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

/// Check that a message is a valid message relative to the previous message.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
///
/// This checks that:
/// - the sequence starts at one if it's the first message
/// - the previous is correctly set to null if it's the first message
/// - the sequence increments correctly
/// - the author has not changed
/// - the feed is not forked
/// - the _actual_ hash matches the hash claimed in `key`
///
/// This does not check:
/// - the signature. See ssb-verify-signatures which lets you to batch verification of signatures.
///
/// `previous_msg_bytes` will be `None` only when `message_bytes` is the first message by that author.
///
/// # Example
///```
///use ssb_validate::validate_message_hash_chain;
///let valid_message_1 = r##"{
///  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
///  "value": {
///    "previous": null,
///    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "sequence": 1,
///    "timestamp": 1470186877575,
///    "hash": "sha256",
///    "content": {
///      "type": "about",
///      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///      "name": "Piet"
///    },
///    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
///  },
///  "timestamp": 1571140551481
///}"##;
///let valid_message_2 = r##"{
///  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
///  "value": {
///    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
///    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "sequence": 2,
///    "timestamp": 1470187292812,
///    "hash": "sha256",
///    "content": {
///      "type": "about",
///      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///      "image": {
///        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
///        "size": 642763,
///        "type": "image/png",
///        "width": 512,
///        "height": 512
///      }
///    },
///    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
///  },
///  "timestamp": 1571140551485
///}"##;
/// let result = validate_message_hash_chain(valid_message_2.as_bytes(), Some(valid_message_1));
/// assert!(result.is_ok());
///```
pub fn validate_message_hash_chain<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    message_bytes: T,
    previous_msg_bytes: Option<U>,
) -> Result<()> {
    let message_bytes = message_bytes.as_ref();
    // msg seq is 1 larger than previous
    let (previous_value, previous_key) = match previous_msg_bytes {
        Some(message) => {
            let previous =
                from_slice::<SsbMessage>(message.as_ref()).context(InvalidPreviousMessage {
                    message: message.as_ref().to_owned(),
                })?;
            (Some(previous.value), Some(previous.key))
        }

        None => (None, None),
    };

    let message = from_slice::<SsbMessage>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    let message_value = message.value;

    message_value_common_checks(
        &message_value,
        previous_value.as_ref(),
        message_bytes,
        previous_key.as_ref(),
    )?;

    let verifiable_msg: Value = from_slice(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    // Get the value from the message as this is what was hashed
    let verifiable_msg_value = match verifiable_msg {
        Value::Object(ref o) => o.get("value").context(InvalidMessageNoValue)?,
        _ => panic!(),
    };

    // Get the "value" from the message as bytes that we can hash.
    let value_bytes =
        to_vec(verifiable_msg_value, false).context(InvalidMessageCouldNotSerializeValue)?;

    let message_actual_multihash = multihash_from_bytes(&value_bytes);

    // The hash of the "value" must match the claimed value stored in the "key"
    ensure!(
        message_actual_multihash == message.key,
        ActualHashDidNotMatchKey {
            message: message_bytes.to_owned(),
            actual_hash: message_actual_multihash,
            expected_hash: message.key,
        }
    );

    Ok(())
}

/// Check that a message is a valid message relative to the previous message.
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
///
/// This checks that:
/// - the sequence starts at one if it's the first message
/// - the previous is correctly set to null if it's the first message
/// - the sequence increments correctly
/// - the author has not changed
/// - the feed is not forked
///
/// This does not check:
/// - the signature. See ssb-verify-signatures which lets you to batch verification of signatures.
///
/// `previous_msg_bytes` will be `None` only when `message_bytes` is the first message by that author.
///
/// # Example
///```
///use ssb_validate::validate_message_value_hash_chain;
///let valid_message_1 = r##"{
///  "previous": null,
///  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///  "sequence": 1,
///  "timestamp": 1470186877575,
///  "hash": "sha256",
///  "content": {
///    "type": "about",
///    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "name": "Piet"
///  },
///  "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
///}"##;
///let valid_message_2 = r##"{
///  "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
///  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///  "sequence": 2,
///  "timestamp": 1470187292812,
///  "hash": "sha256",
///  "content": {
///    "type": "about",
///    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "image": {
///      "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
///      "size": 642763,
///      "type": "image/png",
///      "width": 512,
///      "height": 512
///    }
///  },
///  "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
///}"##;
///
/// let result = validate_message_value_hash_chain(valid_message_2.as_bytes(),
/// Some(valid_message_1.as_bytes()));
/// assert!(result.is_ok());
///```
pub fn validate_message_value_hash_chain<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    message_bytes: T,
    previous_msg_bytes: Option<U>,
) -> Result<()> {
    let message_bytes = message_bytes.as_ref();
    // msg seq is 1 larger than previous
    let (previous_value, previous_key) = match previous_msg_bytes {
        Some(message) => {
            let previous = from_slice::<SsbMessageValue>(message.as_ref()).context(
                InvalidPreviousMessage {
                    message: message.as_ref().to_owned(),
                },
            )?;
            let previous_key = multihash_from_bytes(message.as_ref());
            (Some(previous), Some(previous_key))
        }
        None => (None, None),
    };

    let message_value = from_slice::<SsbMessageValue>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    message_value_common_checks(
        &message_value,
        previous_value.as_ref(),
        message_bytes,
        previous_key.as_ref(),
    )?;

    Ok(())
}

fn multihash_from_bytes(bytes: &[u8]) -> Multihash {
    let value_bytes_latin = node_buffer_binary_serializer(std::str::from_utf8(bytes).unwrap());
    let value_hash = Sha256::digest(value_bytes_latin.as_slice());
    Multihash::Message(value_hash.into())
}

fn message_value_common_checks(
    message_value: &SsbMessageValue,
    previous_value: Option<&SsbMessageValue>,
    message_bytes: &[u8],
    previous_key: Option<&Multihash>,
) -> Result<()> {
    if let Some(previous_value) = previous_value {
        // The authors are not allowed to change in a feed.
        ensure!(
            message_value.author == previous_value.author,
            AuthorsDidNotMatch {
                previous_author: previous_value.author.clone(),
                author: message_value.author.clone()
            }
        );

        // The sequence must increase by one.
        let expected_sequence = previous_value.sequence + 1;
        ensure!(
            message_value.sequence == expected_sequence,
            InvalidSequenceNumber {
                message: message_bytes.to_owned(),
                actual: message_value.sequence,
                expected: expected_sequence
            }
        );

        // msg previous must match hash of previous.value otherwise it's a fork.
        ensure!(
            message_value.previous.as_ref().context(PreviousWasNull)?
                == previous_key.expect("expected the previous key to be Some(key), was None"),
            ForkedFeed {
                previous_seq: previous_value.sequence
            }
        );
    } else {
        //This message is the first message.

        //Seq must be 1
        ensure!(
            message_value.sequence == 1,
            FirstMessageDidNotHaveSequenceOfOne {
                message: message_bytes.to_owned()
            }
        );
        //Previous must be None
        ensure!(
            message_value.previous.is_none(),
            FirstMessageDidNotHavePreviousOfNull {
                message: message_bytes.to_owned()
            }
        );
    };
    Ok(())
}

/// FML, scuttlebutt is miserable.
///
/// This is what node's `Buffer.new(messageString, 'binary')` does. Who knew?
/// So, surprise, but the way ssb encodes messages for signing vs the way it encodes them for
/// hashing is different.
///
fn node_buffer_binary_serializer(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .map(|word| (word & 0xFF) as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        par_validate_message_hash_chain_of_feed, par_validate_ooo_message_hash_chain_of_feed,
        validate_message_hash_chain, validate_message_value_hash_chain,
        validate_ooo_message_hash_chain, Error,
    };
    // NEW TESTS BEGIN
    #[test]
    fn it_works_ooo_messages_without_first_message() {
        assert!(
            validate_ooo_message_hash_chain(MESSAGE_2.as_bytes(), Some(MESSAGE_3.as_bytes()))
                .is_ok()
        );
    }
    #[test]
    fn it_works_ooo_messages() {
        assert!(
            validate_ooo_message_hash_chain(MESSAGE_3.as_bytes(), Some(MESSAGE_1.as_bytes()))
                .is_ok()
        );
    }
    #[test]
    fn par_validate_ooo_message_hash_chain_of_feed_with_first_message_works() {
        let messages = [
            MESSAGE_1.as_bytes(),
            MESSAGE_3.as_bytes(),
            MESSAGE_2.as_bytes(),
        ];

        let result = par_validate_ooo_message_hash_chain_of_feed(&messages[..]);
        assert!(result.is_ok());
    }
    #[test]
    fn par_validate_ooo_message_hash_chain_of_feed_without_first_message_works() {
        let messages = [MESSAGE_3.as_bytes(), MESSAGE_2.as_bytes()];

        let result = par_validate_ooo_message_hash_chain_of_feed(&messages[..]);
        assert!(result.is_ok());
    }
    // NEW TESTS END
    #[test]
    fn it_works_first_message() {
        assert!(validate_message_hash_chain::<_, &[u8]>(MESSAGE_1.as_bytes(), None).is_ok());
    }
    #[test]
    fn it_works_second_message() {
        assert!(
            validate_message_hash_chain(MESSAGE_2.as_bytes(), Some(MESSAGE_1.as_bytes())).is_ok()
        );
    }

    #[test]
    fn it_works_first_message_value() {
        assert!(
            validate_message_value_hash_chain::<_, &[u8]>(MESSAGE_VALUE_1.as_bytes(), None).is_ok()
        );
    }
    #[test]
    fn it_works_second_message_value() {
        assert!(validate_message_value_hash_chain(
            MESSAGE_VALUE_2.as_bytes(),
            Some(MESSAGE_VALUE_1.as_bytes())
        )
        .is_ok());
    }
    #[test]
    fn par_validate_message_hash_chain_of_feed_first_messages_works() {
        let messages = [MESSAGE_1.as_bytes(), MESSAGE_2.as_bytes()];

        let result = par_validate_message_hash_chain_of_feed::<_, &[u8]>(&messages[..], None);
        assert!(result.is_ok());
    }
    #[test]
    fn par_validate_message_hash_chain_of_feed_with_prev_works() {
        let messages = [MESSAGE_2.as_bytes(), MESSAGE_3.as_bytes()];

        let result =
            par_validate_message_hash_chain_of_feed(&messages[..], Some(MESSAGE_1.as_bytes()));
        assert!(result.is_ok());
    }
    #[test]
    fn first_message_must_have_previous_of_null() {
        let result =
            validate_message_hash_chain::<_, &[u8]>(MESSAGE_1_INVALID_PREVIOUS.as_bytes(), None);
        match result {
            Err(Error::FirstMessageDidNotHavePreviousOfNull { message: _ }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn first_message_must_have_sequence_of_one() {
        let result =
            validate_message_hash_chain::<_, &[u8]>(MESSAGE_1_INVALID_SEQ.as_bytes(), None);
        match result {
            Err(Error::FirstMessageDidNotHaveSequenceOfOne { message: _ }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_incorrect_seq() {
        let result = validate_message_hash_chain(
            MESSAGE_2_INCORRECT_SEQUENCE.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::InvalidSequenceNumber {
                message: _,
                actual,
                expected,
            }) => {
                assert_eq!(actual, 3);
                assert_eq!(expected, 2);
            }
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_incorrect_author() {
        let result = validate_message_hash_chain(
            MESSAGE_2_INCORRECT_AUTHOR.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::AuthorsDidNotMatch {
                previous_author: _,
                author: _,
            }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_incorrect_previous_of_null() {
        let result = validate_message_hash_chain(
            MESSAGE_2_PREVIOUS_NULL.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::PreviousWasNull) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_incorrect_key() {
        let result = validate_message_hash_chain(
            MESSAGE_2_INCORRECT_KEY.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::ActualHashDidNotMatchKey {
                message: _,
                expected_hash: _,
                actual_hash: _,
            }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_fork() {
        let result =
            validate_message_hash_chain(MESSAGE_2_FORK.as_bytes(), Some(MESSAGE_1.as_bytes()));
        match result {
            Err(Error::ForkedFeed { previous_seq: 1 }) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn it_validates_a_message_with_unicode() {
        let result = validate_message_hash_chain(
            MESSAGE_WITH_UNICODE.as_bytes(),
            Some(MESSAGE_WITH_UNICODE_PREV.as_bytes()),
        );

        assert!(result.is_ok());
    }

    const MESSAGE_1: &str = r##"{
  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "value": {
    "previous": null,
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 1,
    "timestamp": 1470186877575,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "name": "Piet"
    },
    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
  },
  "timestamp": 1571140551481
}"##;
    const MESSAGE_VALUE_1: &str = r##"{
  "previous": null,
  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
  "sequence": 1,
  "timestamp": 1470186877575,
  "hash": "sha256",
  "content": {
    "type": "about",
    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "name": "Piet"
  },
  "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
}"##;
    const MESSAGE_1_INVALID_SEQ: &str = r##"{
  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "value": {
    "previous": null,
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 0,
    "timestamp": 1470186877575,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "name": "Piet"
    },
    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
  },
  "timestamp": 1571140551481
}"##;
    const MESSAGE_1_INVALID_PREVIOUS: &str = r##"{
  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 1,
    "timestamp": 1470186877575,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "name": "Piet"
    },
    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
  },
  "timestamp": 1571140551481
}"##;

    const MESSAGE_2: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

    const MESSAGE_VALUE_2: &str = r##"{
  "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
  "sequence": 2,
  "timestamp": 1470187292812,
  "hash": "sha256",
  "content": {
    "type": "about",
    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "image": {
      "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
      "size": 642763,
      "type": "image/png",
      "width": 512,
      "height": 512
    }
  },
  "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
}"##;
    const MESSAGE_3: &str = r##"{
  "key": "%VhHgLpaLfY/2/g4+WEhKv5DdXM1V1PCVW1u2kbkvTbY=.sha256",
  "value": {
    "previous": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 3,
    "timestamp": 1470187303671,
    "hash": "sha256",
    "content": {
      "type": "contact",
      "contact": "@8HsIHUvTaWg8IXHpsb8dmDtKH8qLOrSNwNm298OkGoY=.ed25519",
      "following": true,
      "blocking": false
    },
    "signature": "PWhsT9c8HQMhJEohV0tF5mfSnZy0rU0CInnvah+whlMuYDQAjzpmW9be9X8eWVAsqbepS+5I7A7ttvwEonSaBg==.sig.ed25519"
  },
  "timestamp": 1571140551497
}"##;

    const MESSAGE_2_PREVIOUS_NULL: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": null,
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;
    //This message will not hash correctly AND would fail signature verification. But an attacker
    //could publish a message that had correct hashes and signatures.
    const MESSAGE_2_INCORRECT_AUTHOR: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@xzSRT0HSAqGuqu5HxJvqxtp2FJGpt5nRPIHMznLoBao=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;
    const MESSAGE_2_INCORRECT_SEQUENCE: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 3,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;
    const MESSAGE_2_INCORRECT_KEY: &str = r##"{
  "key": "%KLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

    const MESSAGE_2_FORK: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/V5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

    const MESSAGE_WITH_UNICODE: &str = r##"{
  "key": "%lYAK7Lfigw00zMt/UtVg5Ol9XdR4BHWUCxq4r2Ops90=.sha256",
  "value": {
    "previous": "%yV9QaYDbkEHl4W8S8hVf/3TUuvs0JUrOP945jLLK/2c=.sha256",
    "author": "@vt8uK0++cpFioCCBeB3p3jdx4RIdQYJOL/imN1Hv0Wk=.ed25519",
    "sequence": 36,
    "timestamp": 1445502075082,
    "hash": "sha256",
    "content": {
      "type": "post",
      "text": "Web frameworks.\n\n    Much industrial production in the late nineteenth century depended on skilled workers, whose knowledge of the production process often far exceeded their employers’; Taylor saw that this gave laborers a tremendous advantage over their employer in the struggle over the pace of work.\n\n    Not only could capitalists not legislate techniques they were ignorant of, but they were also in no position to judge when workers told them the process simply couldn’t be driven any faster. Work had to be redesigned so that employers did not depend on their employees for knowledge of the production process.\n\nhttps://www.jacobinmag.com/2015/04/braverman-gramsci-marx-technology/"
    },
    "signature": "FbDXlQtC2FQukU8svM5dOALN6QpxFhUHZaC7jTSXdOH7yqDfUlaj8q97YLdo5YqknZ71b0Y59hlQkmfkbtv5DA==.sig.ed25519"
  },
  "timestamp": 1571140555382.0059
}"##;

    const MESSAGE_WITH_UNICODE_PREV: &str = r##"{
  "key": "%yV9QaYDbkEHl4W8S8hVf/3TUuvs0JUrOP945jLLK/2c=.sha256",
  "value": {
    "previous": "%fG8VUZqsl1034p8W+q3vFggEB074qj0hmRPamqq5TH4=.sha256",
    "author": "@vt8uK0++cpFioCCBeB3p3jdx4RIdQYJOL/imN1Hv0Wk=.ed25519",
    "sequence": 35,
    "timestamp": 1445499413793,
    "hash": "sha256",
    "content": {
      "type": "post",
      "text": "something non-linear is happening between 15 and 20 nodes [results.txt](&cwcDjgpJoPG1vjICsTutqfBi1gpNPa8ggl4fep1qCXc=.sha256)",
      "mentions": [
        {
          "link": "&cwcDjgpJoPG1vjICsTutqfBi1gpNPa8ggl4fep1qCXc=.sha256"
        }
      ]
    },
    "signature": "9Dh6hj/gdrruYNh/rkELEJrk0+quhQF1VfU7veJ8Yb/cDUHzaQWue2YljRuERThlyd+92cOfA4PujfNC2VbTDA==.sig.ed25519"
  },
  "timestamp": 1571140555382.002
}"##;
}
