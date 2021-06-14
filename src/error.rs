use snafu::Snafu;
use ssb_legacy_msg_data::json::{DecodeJsonError, EncodeJsonError};
use ssb_multiformats::multihash::Multihash;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
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
    #[snafu(display("Message must have keys in correct order",))]
    InvalidMessageValueOrder { message: Vec<u8> },
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
    #[snafu(display("The message hash must be 'sha256'",))]
    InvalidHashFunction { message: Vec<u8> },
    #[snafu(display("The message content string must be canonical base64",))]
    InvalidBase64 { message: Vec<u8> },
    #[snafu(display("The message value must not be longer than 8192 UTF-16 code units",))]
    InvalidMessageValueLength { message: Vec<u8> },
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
