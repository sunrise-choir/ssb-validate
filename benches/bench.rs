use criterion::{black_box, criterion_group, criterion_main, Criterion};
use flumedb::OffsetLog;
use ssb_legacy_msg_data::json;
use ssb_validate::message::{
    par_validate_message_hash_chain_of_feed, validate_message_hash_chain, SsbMessage,
};
use ssb_validate::message_value::{
    par_validate_message_value, par_validate_message_value_hash_chain_of_feed,
    validate_message_value, validate_message_value_hash_chain,
};

/// Benchmark validation of a single message value in isolation (single-threaded).
pub fn validate_message_value_bench(c: &mut Criterion) {
    let in_log = OffsetLog::<u32>::open_read_only("./test_vecs/piet.offset").unwrap();

    let msg = in_log
        .iter()
        .map(|entry| entry.data)
        .take(1)
        .collect::<Vec<_>>();

    let message = json::from_slice::<SsbMessage>(&msg[0].as_ref()).unwrap();
    let message_value = message.value;
    let value_bytes = json::to_vec(&message_value, false).unwrap();

    c.bench_function("validate_message_value", |b| {
        b.iter(|| {
            let res = validate_message_value(black_box(&value_bytes));
            assert!(res.is_ok());
        })
    });
}

/// Benchmark batch validation of single message values in isolation (multi-threaded).
pub fn par_validate_message_value_bench(c: &mut Criterion) {
    let in_log = OffsetLog::<u32>::open_read_only("./test_vecs/piet.offset").unwrap();

    let msgs = in_log
        .iter()
        .map(|entry| entry.data)
        .take(1000)
        .collect::<Vec<_>>();

    let mut msg_value_bytes = Vec::new();
    for msg in msgs {
        let message = json::from_slice::<SsbMessage>(&msg.as_ref()).unwrap();
        let message_value = message.value;
        let value_bytes = json::to_vec(&message_value, false).unwrap();
        msg_value_bytes.push(value_bytes);
    }

    c.bench_function("par_validate_message_value", |b| {
        b.iter(|| {
            let res = par_validate_message_value(black_box(&msg_value_bytes));
            assert!(res.is_ok());
        })
    });
}

/// Benchmark validation of a message value hash chain (single-threaded).
pub fn validate_message_value_hash_chain_bench(c: &mut Criterion) {
    let in_log = OffsetLog::<u32>::open_read_only("./test_vecs/piet.offset").unwrap();

    let msgs = in_log
        .iter()
        .map(|entry| entry.data)
        .take(2)
        .collect::<Vec<_>>();

    let mut msg_value_bytes = Vec::new();
    for msg in msgs {
        let message = json::from_slice::<SsbMessage>(&msg.as_ref()).unwrap();
        let message_value = message.value;
        let value_bytes = json::to_vec(&message_value, false).unwrap();
        msg_value_bytes.push(value_bytes);
    }

    c.bench_function("validate_message_value_hash_chain", |b| {
        b.iter(|| {
            let res = validate_message_value_hash_chain::<_, &[u8]>(
                black_box(msg_value_bytes[1].clone()),
                Some(&msg_value_bytes[0]),
            );
            assert!(res.is_ok());
        })
    });
}

/// Benchmark batch validation of a message value hash chain (multi-threaded).
pub fn par_validate_message_value_hash_chain_bench(c: &mut Criterion) {
    let in_log = OffsetLog::<u32>::open_read_only("./test_vecs/piet.offset").unwrap();

    let msgs = in_log
        .iter()
        .map(|entry| entry.data)
        .take(1000)
        .collect::<Vec<_>>();

    let mut msg_value_bytes = Vec::new();
    for msg in msgs {
        let message = json::from_slice::<SsbMessage>(&msg.as_ref()).unwrap();
        let message_value = message.value;
        let value_bytes = json::to_vec(&message_value, false).unwrap();
        msg_value_bytes.push(value_bytes);
    }

    c.bench_function("par_validate_message_value_hash_chain", |b| {
        b.iter(|| {
            let res = par_validate_message_value_hash_chain_of_feed::<_, &[u8]>(
                black_box(&msg_value_bytes),
                None,
            );
            assert!(res.is_ok());
        })
    });
}

/// Benchmark validation of a message (`KVT`) hash chain (single-threaded).
pub fn validate_message_bench(c: &mut Criterion) {
    let in_log = OffsetLog::<u32>::open_read_only("./test_vecs/piet.offset").unwrap();

    let msgs = in_log
        .iter()
        .map(|entry| entry.data)
        .take(2)
        .collect::<Vec<_>>();

    c.bench_function("validate_message", |b| {
        b.iter(|| {
            let res =
                validate_message_hash_chain::<_, &[u8]>(black_box(msgs[1].clone()), Some(&msgs[0]));
            assert!(res.is_ok());
        })
    });
}

/// Benchmark batch validation of a message (`KVT`) hash chain (multi-threaded).
pub fn par_validate_messages_bench(c: &mut Criterion) {
    let in_log = OffsetLog::<u32>::open_read_only("./test_vecs/piet.offset").unwrap();

    let msgs = in_log
        .iter()
        .map(|entry| entry.data)
        .take(1000)
        .collect::<Vec<_>>();

    c.bench_function("par_validate_batch", |b| {
        b.iter(|| {
            let res = par_validate_message_hash_chain_of_feed::<_, &[u8]>(black_box(&msgs), None);
            assert!(res.is_ok());
        })
    });
}

criterion_group!(validate_single, validate_message_bench);
criterion_group! {
    name = par_validate_batch;
    config = Criterion::default().sample_size(10);
    targets = par_validate_messages_bench
}
criterion_group!(validate_single_value, validate_message_value_bench);
criterion_group! {
    name = par_validate_single_value;
    config = Criterion::default().sample_size(10);
    targets = par_validate_message_value_bench
}
criterion_group!(
    validate_value_chain,
    validate_message_value_hash_chain_bench
);
criterion_group! {
    name = par_validate_value_chain;
    config = Criterion::default().sample_size(10);
    targets = par_validate_message_value_hash_chain_bench
}
criterion_main!(
    validate_single,
    par_validate_batch,
    validate_single_value,
    par_validate_single_value,
    validate_value_chain,
    par_validate_value_chain,
);
