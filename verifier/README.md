## Getting started
### Step 1.
Generate the proving and verifying keys:

```
cd sp1/crates/prover
RUST_LOG=info make build-circuits
```
### Step 2.
Generate the proofs and json files (for the public values):

cd examples/script
cargo run -- --proof-files

### Step 3.
Compile the wasm module and run the server:
```
wasm-pack build --target web && python -m http.server 8000
```

#### Test

```
wasm-pack test --headless --chrome
```

