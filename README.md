[![Build Status](https://travis-ci.org/sunrise-choir/ssb-validate.svg?branch=master)](https://travis-ci.org/sunrise-choir/ssb-validate)
# ssb-validate

> Verify Secure Scuttlebutt (SSB) hash chains (in parallel)

**THIS FORK DEVIATES SIGNIFICANTLY FROM THE ORIGINAL VERSION!** Support for out-of-order validation (regular and parallel) and multi-author out-of-order validation (regular and parallel) has been added.

## Docs

[Rustdocs](https://sunrise-choir.github.io/ssb-validate/ssb_validate/index.html)

## About

Secure Scuttlebutt "feeds" are a sequence of messages published by one author.
To be valid, a message should satisfy the following criteria:

 - include the hash of the previous message
   - unless it is the first message in feed, in which case previous must be null
 - include a sequence number which is 1 larger than the sequence number of the previous message
   - unless it is the first message in a feed, in which case the sequence number must be 1 and the sequence number of the previous message must be null
 - include a hash function field with value `sha256`
 - the author must not change compared to the previous message
 - if the message includes a key, it must be the hash of the value of the message
 - message value keys must be in the order: "previous", "author"|"sequence", "author"|"sequence", "timestamp", "hash", "content", "signature"
 - the message value must not include extra fields
 - if the message content is a string (encrypted private message) it must be encoded in canonical base64 and end with `.box`

All of the above criteria are validated by this library (either directly or via dependencies).

You can check messages one by one or batch process a collection of them (uses [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html) internally)

In addition to validating messages using all of the above criteria, it is also possible to validate out-of-order messages by satifying a subset of those criteria. This crate provides functions to perform batch validation of such out-of-order messages.

Out-of-order message validation may be performed for single-author or multi-author use-cases (separate functions exist for each case).

When performing validation for out-of-order messages from a single author, the messages must be authored by a single keypair. However, it is not required that the sequence number of a message be 1 larger than the sequence number of the previous message, nor is it required that the hash of the previous message match the hash given for the previous message in a message.

Multi-author out-of-order validation, by contrast to the above, does not perform any checks of the `previous` message. Indeed, it may be said that this method of validation has no concept of a previous message (except that the `previous` field must be present in the message in the correct order).

## Benchmarks

Benchmarking on a 2016 2 core i5 shows that batch processing  is ~3.6 times faster than using [verify_message] 

Benchmarking on Android on a [One Plus 5T](https://en.wikipedia.org/wiki/OnePlus_5T) (8 core arm64) shows that batch processing with [par_verify_messages] is ~9.9 times faster than using [verify_message]! 

