use lazy_static::lazy_static;
use regex::{bytes::Regex as RegexBytes, Regex};
use sha2::{Digest, Sha256};
use snafu::ResultExt;
use ssb_multiformats::multihash::Multihash;

use crate::error::{InvalidMessageCouldNotSerializeValue, Result};
use crate::message_value::SsbMessageValue;

pub fn is_canonical_base64(private_msg: &str) -> bool {
    lazy_static! {
        // Regex pattern to match on canonical base64 for private messages
        // Implemented according to the `is-canonical-base64` JS module by dominictarr
        static ref RE: Regex = Regex::new(r"^(?:[a-zA-Z0-9/+]{4})*(?:[a-zA-Z0-9/+](?:(?:[AQgw]==)|(?:[a-zA-Z0-9/+][AEIMQUYcgkosw048]=)))?.box.*$").unwrap();
    }
    RE.is_match(private_msg)
}

pub fn is_correct_length(msg_value: &SsbMessageValue) -> Result<bool> {
    // the second arg is used to set `compact` to `false` (preserves whitespace)
    let msg_value_str = ssb_legacy_msg_data::json::to_string(msg_value, false)
        .context(InvalidMessageCouldNotSerializeValue)?;
    let msg_len: usize = msg_value_str.chars().map(|ch| ch.len_utf16()).sum();
    if msg_len > 8192 {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub fn is_correct_order(bytes: &[u8]) -> bool {
    lazy_static! {
        static ref RE_B: RegexBytes = RegexBytes::new(r#""previous"[\s\S]*("author"|"sequence")[\s\S]*("author"|"sequence")[\s\S]*"timestamp"[\s\S]*"hash"[\s\S]*"content"[\s\S]*"signature""#).unwrap();
    }
    RE_B.is_match(bytes)
}

pub fn multihash_from_bytes(bytes: &[u8]) -> Multihash {
    let value_bytes_latin = node_buffer_binary_serializer(std::str::from_utf8(bytes).unwrap());
    let value_hash = Sha256::digest(value_bytes_latin.as_slice());
    Multihash::Message(value_hash.into())
}

/// FML, scuttlebutt is miserable.
///
/// This is what node's `Buffer.new(messageString, 'binary')` does. Who knew?
/// So, surprise, but the way ssb encodes messages for signing vs the way it encodes them for
/// hashing is different.
///
pub fn node_buffer_binary_serializer(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .map(|word| (word & 0xFF) as u8)
        .collect()
}
