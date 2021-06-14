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
pub mod error;
pub mod message;
pub mod message_value;
pub mod test_data;
pub mod utils;
