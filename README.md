# gnark BN254 Verifier

The `gnark-bn254-verifier` crate is used for verifying Groth16 and PlonK proofs on the `Bn254` curve, ensuring compatibility with proofs generated by the `gnark` library. One can save proofs and verification keys from `gnark` and subsequently load them to this library for verifying the proofs with ease.

### How to save proofs and verification keys from gnark

To save the proof and verification key from `gnark`, one can use the following code snippet:

```go
// Write the verifier key.
vkFile, err := os.Create("vk.bin")
if err != nil {
    panic(err)
}
defer vkFile.Close()
_, err = vk.WriteTo(vkFile)
if err != nil {
    panic(err)
}

// Write the proving key.
proofFile, err := os.Create("proof.bin")
if err != nil {
    panic(err)
}
defer proofFile.Close()
_, err = proof.WriteTo(proofFile)
if err != nil {
    panic(err)
}
```

## Usage

To use this library, add it as a dependency in your `Cargo.toml`:
```toml
[dependencies]
gnark-bn254-verifier = { git = "https://github.com/Bisht13/gnark-bn254-verifier.git", branch = "main" }
```

Then, you can verify a proof by calling the `verify` function:
```rs
use ark_bn254::Fr;
use gnark_bn254_verifier::{verify, ProvingSystem};

fn main() {

    let proof = vec![0u8; 1000];
    let vk = vec![0u8; 1000];

    if verify(&proof, &vk, &[Fr::from(1u8), Fr::from(7u8)], ProvingSystem::Plonk) {
        println!("Proof is valid");
    } else {
        println!("Proof is invalid");
    }
}

```

## Features

- Verification of Groth16 and PlonK proofs generated using `gnark`.
- Easy integration into Rust projects.