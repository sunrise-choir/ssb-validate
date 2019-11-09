use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use ssb_legacy_msg_data::json::{from_slice, to_vec, DecodeJsonError, EncodeJsonError};
use ssb_legacy_msg_data::value::Value;
use ssb_legacy_msg_data::LegacyF64;
use ssb_multiformats::multihash::{Multihash, Target};

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
    ActualHashDidNotMatchKey,
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

/// Check that a message is a valid relative to it's previous message.
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
pub fn validate_hash_chain(message_bytes: &[u8], previous_msg_bytes: Option<&[u8]>) -> Result<()> {
    // msg seq is 1 larger than previous
    let previous_message = match previous_msg_bytes {
        Some(message) => Some(from_slice::<SsbMessage>(message).context(
            InvalidPreviousMessage {
                message: message.to_owned(),
            },
        )?),
        None => None,
    };

    let message = from_slice::<SsbMessage>(message_bytes).context(InvalidMessage {
        message: message_bytes.to_owned(),
    })?;

    if let Some(previous) = previous_message {
        // The authors are not allowed to change in a feed.
        let previous_author = previous.value.author;
        let author = message.value.author;
        ensure!(
            author == previous_author,
            AuthorsDidNotMatch {
                previous_author,
                author
            }
        );

        // The sequence must increase by one.
        let expected_sequence = previous.value.sequence + 1;
        ensure!(
            message.value.sequence == expected_sequence,
            InvalidSequenceNumber {
                message: message_bytes.to_owned(),
                actual: message.value.sequence,
                expected: expected_sequence
            }
        );

        // msg previous must match hash of previous.value otherwise it's a fork.
        ensure!(
            message.value.previous.context(PreviousWasNull)? == previous.key,
            ForkedFeed {
                previous_seq: previous.value.sequence
            }
        );
    } else {
        //This message is the first message.

        //Seq must be 1
        ensure!(
            message.value.sequence == 1,
            FirstMessageDidNotHaveSequenceOfOne {
                message: message_bytes.to_owned()
            }
        );
        //Previous must be None
        ensure!(
            message.value.previous.is_none(),
            FirstMessageDidNotHavePreviousOfNull {
                message: message_bytes.to_owned()
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
    let mut hasher = Sha256::new();
    hasher.input(value_bytes);
    let value_hash = hasher.result();

    let message_actual_multihash = Multihash::from_sha256(value_hash.into(), Target::Message);

    // The hash of the "value" must match the claimed value stored in the "key"
    ensure!(
        message_actual_multihash == message.key,
        ActualHashDidNotMatchKey
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{validate_hash_chain, Error};

    #[test]
    fn it_works_first_message() {
        assert!(validate_hash_chain(MESSAGE_1.as_bytes(), None).is_ok());
    }
    #[test]
    fn it_works_second_message() {
        assert!(validate_hash_chain(MESSAGE_2.as_bytes(), Some(MESSAGE_1.as_bytes())).is_ok());
    }
    #[test]
    fn first_message_must_have_previous_of_null() {
        let result = validate_hash_chain(MESSAGE_1_INVALID_PREVIOUS.as_bytes(), None);
        match result {
            Err(Error::FirstMessageDidNotHavePreviousOfNull { message: _ }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn first_message_must_have_sequence_of_one() {
        let result = validate_hash_chain(MESSAGE_1_INVALID_SEQ.as_bytes(), None);
        match result {
            Err(Error::FirstMessageDidNotHaveSequenceOfOne { message: _ }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_incorrect_seq() {
        let result = validate_hash_chain(
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
        let result = validate_hash_chain(
            MESSAGE_2_INCORRECT_AUTHOR.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::AuthorsDidNotMatch{previous_author: _, author: _}) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_incorrect_previous_of_null() {
        let result = validate_hash_chain(
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
        let result = validate_hash_chain(
            MESSAGE_2_INCORRECT_KEY.as_bytes(),
            Some(MESSAGE_1.as_bytes()),
        );
        match result {
            Err(Error::ActualHashDidNotMatchKey) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn it_detects_fork() {
        let result = validate_hash_chain(MESSAGE_2_FORK.as_bytes(), Some(MESSAGE_1.as_bytes()));
        match result {
            Err(Error::ForkedFeed { previous_seq: 1 }) => {}
            _ => panic!(),
        }
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
}
