//! Functions for validating message values (ie. just the `value` without `key` and `timestamp`).
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt, ResultExt};
use ssb_legacy_msg_data::{
    json::from_slice,
    value::{ContentValue, Value},
    LegacyF64,
};
use ssb_multiformats::multihash::Multihash;

use crate::error::{
    AuthorsDidNotMatch, FirstMessageDidNotHavePreviousOfNull, FirstMessageDidNotHaveSequenceOfOne,
    ForkedFeed, InvalidBase64, InvalidHashFunction, InvalidMessage, InvalidMessageValueLength,
    InvalidMessageValueOrder, InvalidPreviousMessage, InvalidSequenceNumber, PreviousWasNull,
    Result,
};
use crate::utils;

/// Data type representing the `value` of a message object (`KVT`). More information concerning the
/// data model can be found
/// in the [`Metadata` documentation](https://spec.scuttlebutt.nz/feed/messages.html#metadata).
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SsbMessageValue {
    pub previous: Option<Multihash>,
    pub author: String,
    pub sequence: u64,
    pub timestamp: LegacyF64,
    pub hash: String,
    pub content: ContentValue,
    pub signature: String,
}

/// Batch validates a collection of message values, all by the same author, ordered by ascending sequence
/// number, with no missing messages.
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
///use ssb_validate::message_value::par_validate_message_value_hash_chain_of_feed;
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
                    let prev = previous.map(|prev| prev.as_ref().to_owned());
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
///use ssb_validate::message_value::validate_message_value_hash_chain;
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
            let previous_key = utils::multihash_from_bytes(message.as_ref());
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
        // run checks for previous msg
        true,
    )?;

    Ok(())
}

/// Check that a message value is valid (in isolation).
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
///
/// - The fields (keys) of the message value are in the correct order
/// - The hash signature is `sha256`
/// - The message `content` is canonical base64 (if `content` is a string)
/// - The message value does not exceed 8192 UTF-16 code units when serialized as a JSON string
///
/// This does not check:
///
/// - The signature. See ssb-verify-signatures which lets you to batch verification of signatures.
/// - Anything to do with the `previous` message.
pub fn validate_message_value<T: AsRef<[u8]>>(message_bytes: T) -> Result<()> {
    let message_bytes = message_bytes.as_ref();
    let message_value = from_slice::<SsbMessageValue>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    // perform common validation checks without `previous` message
    message_value_common_checks(&message_value, None, message_bytes, None, false)?;

    Ok(())
}

/// Batch validates a collection of message values. Messages are not required to be in order or to
/// be authored by a single identity.
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
pub fn par_validate_message_value<T: AsRef<[u8]>>(messages: &[T]) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
{
    messages
        .par_iter()
        .enumerate()
        .try_fold(|| (), |_, (_idx, msg)| validate_message_value(msg.as_ref()))
        .try_reduce(|| (), |_, _| Ok(()))
}

/// Check that an out-of-order message value is valid.
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
///
/// - The fields (keys) of the message value are in the correct order
/// - The hash signature is `sha256`
/// - The message `content` is canonical base64 (if `content` is a string)
/// - The message value does not exceed 8192 UTF-16 code units when serialized as a JSON string
/// - The `author` of the message value matches the `author` of the previous message value
///
/// This does not check:
///
/// - The signature. See ssb-verify-signatures which lets you to batch verification of signatures
/// - The `sequence` of the message in relation to the previous message
/// - That the hash value for `previous` matches the actual hashed value of the previous message
pub fn validate_ooo_message_value_hash_chain<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    message_bytes: T,
    previous_msg_bytes: Option<U>,
) -> Result<()> {
    let message_bytes = message_bytes.as_ref();
    // we need the value of the `previous` msg to check that the author has not changed
    let previous_value = match previous_msg_bytes {
        Some(message) => {
            let previous = from_slice::<SsbMessageValue>(message.as_ref()).context(
                InvalidPreviousMessage {
                    message: message.as_ref().to_owned(),
                },
            )?;
            Some(previous)
        }
        None => (None),
    };

    let message_value = from_slice::<SsbMessageValue>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    // perform common validation checks without `previous` message
    message_value_common_checks(&message_value, None, message_bytes, None, false)?;

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

    Ok(())
}

/// Batch validates an out-of-order collection of message values from a single author.
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
pub fn par_validate_ooo_message_value_hash_chain_of_feed<T: AsRef<[u8]>, U: AsRef<[u8]>>(
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
                    let prev = previous.map(|prev| prev.as_ref().to_owned());
                    validate_ooo_message_value_hash_chain(msg.as_ref(), prev)
                } else {
                    validate_ooo_message_value_hash_chain(
                        msg.as_ref(),
                        Some(messages[idx - 1].as_ref()),
                    )
                }
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

/// Validation checks which are common across all contexts. The `check_previous` argument is used
/// to control checks for the optional `previous_value` and `previous_key` parameters.
pub fn message_value_common_checks(
    message_value: &SsbMessageValue,
    previous_value: Option<&SsbMessageValue>,
    message_bytes: &[u8],
    previous_key: Option<&Multihash>,
    check_previous: bool,
) -> Result<()> {
    // The message value fields are in the correct order.
    ensure!(
        utils::is_correct_order(message_bytes),
        InvalidMessageValueOrder {
            message: message_bytes.to_owned()
        }
    );

    // The hash signature must be `sha256`.
    ensure!(
        message_value.hash == "sha256",
        InvalidHashFunction {
            message: message_bytes.to_owned()
        }
    );

    // The message `content` string must be canonical base64.
    if let Value::String(private_msg) = &message_value.content.0 {
        ensure!(
            utils::is_canonical_base64(private_msg),
            InvalidBase64 {
                message: message_bytes,
            }
        );
    }

    if check_previous {
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
            // This message is the first message.

            // Sequence must be 1.
            ensure!(
                message_value.sequence == 1,
                FirstMessageDidNotHaveSequenceOfOne {
                    message: message_bytes.to_owned()
                }
            );
            // Previous must be None.
            ensure!(
                message_value.previous.is_none(),
                FirstMessageDidNotHavePreviousOfNull {
                    message: message_bytes.to_owned()
                }
            );
        };
    }

    // The message `value` length must be less than 8192 UTF-16 code units.
    // We check this last since serialization is expensive.
    ensure!(
        utils::is_correct_length(message_value)?,
        InvalidMessageValueLength {
            message: message_bytes.to_owned()
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::message_value::{
        par_validate_message_value, par_validate_message_value_hash_chain_of_feed,
        par_validate_ooo_message_value_hash_chain_of_feed, validate_message_value,
        validate_message_value_hash_chain, validate_ooo_message_value_hash_chain,
    };
    use crate::test_data::{
        MESSAGE_VALUE_1, MESSAGE_VALUE_2, MESSAGE_VALUE_3, MESSAGE_VALUE_3_INCORRECT_AUTHOR,
    };

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
    fn it_validates_an_ordered_sequence_of_message_values_in_parallel() {
        let messages = [
            MESSAGE_VALUE_1.as_bytes(),
            MESSAGE_VALUE_2.as_bytes(),
            MESSAGE_VALUE_3.as_bytes(),
        ];
        let result = par_validate_message_value_hash_chain_of_feed::<_, &[u8]>(&messages[..], None);
        assert!(result.is_ok());
    }

    #[test]
    fn it_validates_a_single_message_value() {
        assert!(validate_message_value(MESSAGE_VALUE_2.as_bytes()).is_ok());
    }

    #[test]
    fn it_validates_message_values_in_parallel() {
        let messages = [MESSAGE_VALUE_1.as_bytes(), MESSAGE_VALUE_2.as_bytes()];
        let result = par_validate_message_value(&messages[..]);
        assert!(result.is_ok());
    }

    #[test]
    fn it_validates_a_pair_of_ooo_message_values() {
        assert!(validate_ooo_message_value_hash_chain(
            MESSAGE_VALUE_2.as_bytes(),
            Some(MESSAGE_VALUE_3.as_bytes())
        )
        .is_ok());
    }

    #[test]
    fn it_validates_ooo_message_values_in_parallel() {
        let messages = [
            MESSAGE_VALUE_3.as_bytes(),
            MESSAGE_VALUE_1.as_bytes(),
            MESSAGE_VALUE_2.as_bytes(),
        ];
        let result =
            par_validate_ooo_message_value_hash_chain_of_feed::<_, &[u8]>(&messages[..], None);
        assert!(result.is_ok());
    }

    #[test]
    fn it_validates_message_values_from_different_authors_in_parallel() {
        let messages = [
            MESSAGE_VALUE_2.as_bytes(),
            MESSAGE_VALUE_3_INCORRECT_AUTHOR.as_bytes(),
        ];
        let result = par_validate_message_value(&messages[..]);
        assert!(result.is_ok());
    }
}
