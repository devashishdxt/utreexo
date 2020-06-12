use criterion::{black_box, criterion_group, criterion_main, Criterion};

use utreexo::{MemoryAccumulator, MemoryForest, Proof, Prover, Utreexo};

const INITIAL_COUNT: usize = 10_000_000;

pub fn criterion_benchmark(c: &mut Criterion) {
    let hashes = gen_hashes();
    let accumulator = gen_accumulator(&hashes);
    let forest = gen_forest(&hashes);
    let proofs = gen_proofs(&forest, &hashes);

    bench_accumulator_insert(c, accumulator.clone());
    bench_accumulator_delete(c, accumulator, &proofs);
    bench_forest_prove(c, &forest, &hashes);
    bench_forest_insert(c, forest);
    bench_forest_delete(c, gen_forest(&hashes), &proofs);
}

fn bench_accumulator_insert(c: &mut Criterion, mut accumulator: MemoryAccumulator) {
    let hash: [u8; 32] = rand::random();

    c.bench_function("accumulator insert", |b| {
        b.iter(|| {
            accumulator.insert(black_box(hash));
        })
    });
}

fn bench_accumulator_delete(
    c: &mut Criterion,
    mut accumulator: MemoryAccumulator,
    proofs: &[Proof],
) {
    let mut proofs_iter = proofs.iter();

    c.bench_function("accumulator delete", |b| {
        b.iter(|| accumulator.delete(black_box(proofs_iter.next().unwrap())))
    });
}

fn bench_forest_insert(c: &mut Criterion, mut forest: MemoryForest) {
    let hash: [u8; 32] = rand::random();

    c.bench_function("forest insert", |b| {
        b.iter(|| {
            forest.insert(black_box(hash));
        })
    });
}

fn bench_forest_delete(c: &mut Criterion, mut forest: MemoryForest, proofs: &[Proof]) {
    let mut proofs_iter = proofs.iter();

    c.bench_function("forest delete", |b| {
        b.iter(|| forest.delete(black_box(proofs_iter.next().unwrap())))
    });
}

fn bench_forest_prove(c: &mut Criterion, forest: &MemoryForest, hashes: &[[u8; 32]]) {
    let mut hashes_iter = hashes.iter();

    c.bench_function("forest prove", |b| {
        b.iter(|| forest.prove(black_box(hashes_iter.next().unwrap())))
    });
}

fn gen_hashes() -> Vec<[u8; 32]> {
    let mut hashes = Vec::with_capacity(INITIAL_COUNT);

    for _ in 0..INITIAL_COUNT {
        let hash: [u8; 32] = rand::random();
        hashes.push(hash.into());
    }

    hashes
}

fn gen_accumulator(hashes: &[[u8; 32]]) -> MemoryAccumulator {
    let mut accumulator = MemoryAccumulator::new();

    for hash in hashes {
        accumulator.insert(*hash);
    }

    accumulator
}

fn gen_forest(hashes: &[[u8; 32]]) -> MemoryForest {
    let mut forest = MemoryForest::new();

    for hash in hashes {
        forest.insert(*hash)
    }

    forest
}

fn gen_proofs(forest: &MemoryForest, hashes: &[[u8; 32]]) -> Vec<Proof> {
    let mut proofs = Vec::with_capacity(INITIAL_COUNT);

    for hash in hashes {
        proofs.push(forest.prove(hash).unwrap());
    }

    proofs
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
