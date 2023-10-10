# fil-wdpost-bench (32GiB)

## Running the benchmarks

1. [Prepare parameter files](https://github.com/filecoin-project/rust-fil-proofs#parameter-file-location)

2. Benchmark Normal

   `CUDA_VISIBLE_DEVICES=0 RUST_LOG=trace cargo run --release`

3. Benchmark Supraseal

   `CUDA_VISIBLE_DEVICES=0 RUST_LOG=trace cargo run --release --features=cuda-supraseal`

## Result

2023-10-10 Results with GeForce RTX 3080

| benchmark           | sector_count | prover time   |
| ------------------- | ------------ | ------------- |
| Benchmark_Normal    | 2349         | 84.702678163s |
| Benchmark_Supraseal | 2349         | 34.980418253s |
