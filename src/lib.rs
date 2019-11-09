use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
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
    InvalidMessageCouldNotSerializeValue{source: EncodeJsonError},
    #[snafu(display("The actual hash of the value did not match the hash claimed by `key`"))]
    ActualHashDidNotMatchKey,
    #[snafu(display("`message.value.previous` did not match the `key` of previous message"))] 
    PreviousWasNotCorrect,
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
        ensure!(message.value.previous.context(PreviousWasNotCorrect)? == previous.key, PreviousWasNotCorrect);
        
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

    
    let verifiable_msg: Value = from_slice(message_bytes).context(InvalidMessage{message: message_bytes.to_owned()})?;

    // Get the value from the message as this is what was hashed
    let verifiable_msg_value = match verifiable_msg {
        Value::Object(ref o) => o.get("value").context(InvalidMessageNoValue)?,
        _ => panic!(),
    };

    // Get the "value" from the message as bytes that we can hash.
    let value_bytes = to_vec(verifiable_msg_value, false).context(InvalidMessageCouldNotSerializeValue)?;
    let mut hasher = Sha256::new();
    hasher.input(value_bytes);
    let value_hash = hasher.result();

    let message_actual_multihash = Multihash::from_sha256(value_hash.into(), Target::Message);

    // The hash of the "value" must match the claimed value stored in the "key"
    ensure!(message_actual_multihash == message.key, ActualHashDidNotMatchKey);


    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
