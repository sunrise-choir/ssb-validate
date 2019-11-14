# ssb-validate

> Verify Secure Scuttlebutt (SSB) hash chains (in parallel)

Secure Scuttlebutt "feeds" are a sequence of messages published by one author.
To be a valid message,
- each message must include the hash of the preceding message
- the sequence number must be one larger than the preceding message
- the author must not change compared to the last preceding message
- If it's the first message in a feed, the sequence must be 1 and the previous must be null.

You can check messages one by one or batch process a collection of them (uses [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html) internally)