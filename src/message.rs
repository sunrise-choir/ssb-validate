//! Functions for validating messages in the form of `KVT` (`key`, `value`, `timestamp`).
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt, ResultExt};
use ssb_legacy_msg_data::{
    json::{from_slice, to_vec},
    value::Value,
};
use ssb_multiformats::multihash::Multihash;

use crate::error::{
    ActualHashDidNotMatchKey, AuthorsDidNotMatch, InvalidMessage,
    InvalidMessageCouldNotSerializeValue, InvalidMessageNoValue, InvalidPreviousMessage, Result,
};
use crate::message_value::{message_value_common_checks, SsbMessageValue};
use crate::utils;

/// Data type representing a `key-value` message object, where the `key` is a hash of the `value`.
#[derive(Serialize, Deserialize, Debug)]
struct SsbMessage {
    key: Multihash,
    value: SsbMessageValue,
}

/// Check that an out-of-order message is valid without checking the author.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
///
/// This checks that:
/// - the _actual_ hash matches the hash claimed in `key`
/// - the message contains the correct fields
/// - the message value fields are in the correct order
/// - there are no unexpected top-level fields in the message
/// - the hash signature is defined as `sha256`
/// - the message `content` string is canonical base64
///
/// This does not check:
/// - the signature (see ssb-verify-signatures which lets you to batch verification of signatures)
/// - the previous message
///   - no check of the sequence to ensure it increments by 1 compared to previous
///   - no check that the _actual_ hash of the previous message matches the hash claimed in `previous`
///   - no check that the author has not changed
pub fn validate_multi_author_message_hash_chain<T: AsRef<[u8]>>(message_bytes: T) -> Result<()> {
    let message_bytes = message_bytes.as_ref();

    let message = from_slice::<SsbMessage>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    let message_value = message.value;

    message_value_common_checks(&message_value, None, message_bytes, None, false)?;

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

    let message_actual_multihash = utils::multihash_from_bytes(&value_bytes);

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

/// Batch validates a collection of out-of-order messages by multiple authors. No previous message
/// checks are performed, meaning that missing messages are allowed, the collection is not expected
/// to be ordered by ascending sequence number and the author is not expected to match between
/// current and previous message.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
pub fn par_validate_multi_author_message_hash_chain_of_feed<T: AsRef<[u8]>>(
    messages: &[T],
) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
{
    messages
        .par_iter()
        .enumerate()
        .try_fold(
            || (),
            |_, (_idx, msg)| validate_multi_author_message_hash_chain(msg.as_ref()),
        )
        .try_reduce(|| (), |_, _| Ok(()))
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

    let message_actual_multihash = utils::multihash_from_bytes(&value_bytes);

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

/// Batch validates a collection of messages, all by the same author, ordered by ascending sequence
/// number, with no missing messages.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
///
/// This will mainly be useful during replication. Collect all the latest messages from a feed you're
/// replicating and batch validate all the messages at once.
///
/// # Example
///```
///use ssb_validate::message::par_validate_message_hash_chain_of_feed;
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
                    let prev = previous.map(|prev| prev.as_ref().to_owned());
                    validate_message_hash_chain(msg.as_ref(), prev)
                } else {
                    validate_message_hash_chain(msg.as_ref(), Some(messages[idx - 1].as_ref()))
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
///use ssb_validate::message::validate_message_hash_chain;
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
        // run checks for previous msg
        true,
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

    let message_actual_multihash = utils::multihash_from_bytes(&value_bytes);

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

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::message::{
        par_validate_message_hash_chain_of_feed,
        par_validate_multi_author_message_hash_chain_of_feed,
        par_validate_ooo_message_hash_chain_of_feed, validate_message_hash_chain,
        validate_multi_author_message_hash_chain, validate_ooo_message_hash_chain,
    };
    use crate::test_data::*;

    #[test]
    fn it_works_multi_author() {
        assert!(validate_multi_author_message_hash_chain(MESSAGE_2.as_bytes()).is_ok());
    }

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
    fn it_validates_a_private_message_ooo() {
        let result = validate_ooo_message_hash_chain::<_, &[u8]>(MESSAGE_PRIVATE.as_bytes(), None);

        assert!(result.is_ok());
    }

    #[test]
    fn it_detects_invalid_base64_for_private_message_ooo() {
        let result =
            validate_ooo_message_hash_chain::<_, &[u8]>(MESSAGE_PRIVATE_INVALID.as_bytes(), None);
        match result {
            Err(Error::InvalidBase64 { message: _ }) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn par_validate_multi_author_message_hash_chain_of_feed_works() {
        let messages = [
            MESSAGE_WITH_UNICODE.as_bytes(),
            MESSAGE_PRIVATE.as_bytes(),
            MESSAGE_1.as_bytes(),
        ];

        let result = par_validate_multi_author_message_hash_chain_of_feed(&messages[..]);
        assert!(result.is_ok());
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
    fn it_detects_incorrect_key_for_multi_author() {
        let result = validate_multi_author_message_hash_chain(MESSAGE_2_INCORRECT_KEY.as_bytes());
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
    fn it_detects_extra_unwanted_field() {
        let result =
            validate_message_hash_chain::<_, &[u8]>(MESSAGE_WITH_EXTRA_FIELD.as_bytes(), None);
        // code: Message("unknown field `extra`, expected one of ...
        match result {
            Err(Error::InvalidMessage {
                source: _,
                message: _,
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
    fn it_detects_missing_hash_function() {
        let result =
            validate_message_hash_chain::<_, &[u8]>(MESSAGE_WITHOUT_HASH_FUNCTION.as_bytes(), None);
        match result {
            Err(Error::InvalidMessage {
                source: _,
                message: _,
            }) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn it_detects_incorrect_hash_function() {
        let result = validate_message_hash_chain::<_, &[u8]>(
            MESSAGE_WITH_INVALID_HASH_FUNCTION.as_bytes(),
            None,
        );
        match result {
            Err(Error::InvalidHashFunction { message: _ }) => {}
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

    #[test]
    fn it_detects_incorrect_message_value_order() {
        let result = validate_message_hash_chain(
            MESSAGE_2_INVALID_ORDER.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::InvalidMessageValueOrder { message: _ }) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn it_validates_a_private_message() {
        let result = validate_message_hash_chain(
            MESSAGE_PRIVATE.as_bytes(),
            Some(MESSAGE_PRIVATE_PREV.as_bytes()),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn it_detects_invalid_base64_for_private_message() {
        let result = validate_message_hash_chain(
            MESSAGE_PRIVATE_INVALID.as_bytes(),
            Some(MESSAGE_PRIVATE_PREV.as_bytes()),
        );
        match result {
            Err(Error::InvalidBase64 { message: _ }) => {}
            _ => panic!(),
        }
    }
}
