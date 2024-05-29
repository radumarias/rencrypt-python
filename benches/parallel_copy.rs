use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rayon::prelude::*;

fn parallel_copy_standard(source: &[u8], destination: &mut [u8]) {
    source.par_iter().zip(destination.par_iter_mut()).for_each(|(&src, dst)| {
        *dst = src;
    });
}

fn parallel_copy_rchunks(source: &[u8], destination: &mut [u8], chunk_size: usize) {
    destination.par_rchunks_mut(chunk_size).zip(source.par_chunks(chunk_size)).for_each(|(dst_chunk, src_chunk)| {
        dst_chunk.copy_from_slice(src_chunk);
    });
}

fn benchmark_parallel_copy(c: &mut Criterion) {
    let source: Vec<u8> = vec![0; 10_000];
    let mut destination: Vec<u8> = vec![0; 10_000];
    let chunk_size = 100;

    c.bench_function("parallel_copy_standard", |b| {
        b.iter(|| parallel_copy_standard(black_box(&source), black_box(&mut destination)))
    });

    c.bench_function("parallel_copy_rchunks", |b| {
        b.iter(|| parallel_copy_rchunks(black_box(&source), black_box(&mut destination), black_box(chunk_size)))
    });
}

criterion_group!(benches, benchmark_parallel_copy);
criterion_main!(benches);
