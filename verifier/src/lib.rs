#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]

//! This crate provides verifiers for Groth16 and Plonk zero-knowledge proofs.
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};

use bn::Fr;
use groth16::{
    error::Groth16Error, load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes,
    verify_groth16,
};
use plonk::{
    error::PlonkError, load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes,
    verify_plonk,
};
use wasm_bindgen::prelude::*;
use serde_json::Value;
use std::panic;
use console_error_panic_hook;
use std::io::Read;
use num_bigint::BigUint;
use num_traits::Num;
use serde_json;
use hex;


// cd sp1/crates/prover
// RUST_LOG=info make build-circuits
const PLONK_VK_BYTES: &[u8] = include_bytes!("../../vk/groth16_vk.bin"); // TODO!
const GROTH16_VK_BYTES: &[u8] = include_bytes!("../../vk/groth16_vk.bin");

//use num_bigint::BigUint;
// use num_traits::Num;
// use sp1_sdk::{SP1ProofWithPublicValues};

// use num_bigint::BigUint;

mod constants;
mod converter;
mod error;
mod groth16;
mod hash_to_field;
mod plonk;
mod transcript;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum ProofMode {
    Groth16,
    Plonk,
}

// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
/// Test
extern {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

// #[wasm_bindgen]
/// WASM to verify a groth16 proof
pub fn verify_groth16_wasm(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, JsValue> {
    let proof = load_groth16_proof_from_bytes(proof)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;
        
    let vk = load_groth16_verifying_key_from_bytes(vk)
        .map_err(|e| JsValue::from_str(&format!("Invalid verification key: {}", e)))?;

    // log("Valid verification key file.");

    Ok(verify_groth16(&vk, &proof, public_inputs).is_ok())
}


// #[wasm_bindgen]
/// WASM to verify a plonk proof
pub fn verify_plonk_wasm(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, JsValue> {
    let proof = load_plonk_proof_from_bytes(proof)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    let vk = load_plonk_verifying_key_from_bytes(vk)
        .map_err(|e| JsValue::from_str(&format!("Invalid verification key: {}", e)))?;

    Ok(verify_plonk(&vk, &proof, public_inputs).is_ok())
}


#[wasm_bindgen]
/// WASM to verify a proof using the specified method
pub fn verify_proof(proof_json: &str, method: ProofMode) -> Result<bool, JsValue> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    // Parse the JSON string
    let json: Value = serde_json::from_str(proof_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;

    // Extract proof and public inputs from JSON
    let raw_proof = json["raw_proof"].as_str()
        .ok_or_else(|| JsValue::from_str("Failed to extract proof from JSON"))?;
    let public_inputs = json["public_inputs"].as_array()
        .ok_or_else(|| JsValue::from_str("Failed to extract public inputs from JSON"))?;

    // Convert hex proof to bytes
    let proof_bytes = hex::decode(raw_proof)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode proof hex: {}", e)))?;

    // Convert public inputs to byte representations
    let vkey_hash = BigUint::from_str_radix(&public_inputs[0].as_str().unwrap(), 10)
        .unwrap()
        .to_bytes_be();
    let committed_values_digest = BigUint::from_str_radix(&public_inputs[1].as_str().unwrap(), 10)
        .unwrap()
        .to_bytes_be();

    let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest = Fr::from_slice(&committed_values_digest)
        .expect("Unable to read committed_values_digest");

    // Read VK from the appropriate binary
    let vk_bytes = match method {
        ProofMode::Groth16 => GROTH16_VK_BYTES,
        ProofMode::Plonk => PLONK_VK_BYTES,
    };

    // Call the appropriate verification function based on the method
    match method {
        ProofMode::Groth16 => verify_groth16_wasm(&proof_bytes, &vk_bytes, &[vkey_hash, committed_values_digest]),
        ProofMode::Plonk => verify_plonk_wasm(&proof_bytes, &vk_bytes, &[vkey_hash, committed_values_digest]),
    }
}

// So SP1ProofWithPublicValues can't be used because SP1 SDK is not compatible with wasm.
#[wasm_bindgen]
/// WASM to verify a proof using SP1 to read proof and public inputs
pub fn verify_proof_sp1(contents: &[u8], method: ProofMode) -> Result<bool, JsValue> {

    panic::set_hook(Box::new(console_error_panic_hook::hook));
    // log("Deserializing proof from buffer");

    // Load the saved proof and convert it to the specified proof mode
    // Passing the bytes directly instead of SP1ProofWithPublicValues::load()
    let sp1_proof_with_public_values: SP1ProofWithPublicValues = bincode::deserialize(contents)
        .expect("Failed to deserialize proof.");

    // log(&format!("Proof: {:?}", sp1_proof_with_public_values));

    let (raw_proof, public_inputs) = match method {
        ProofMode::Groth16 => {
            // log(&format!("Proof mode: Groth16"));
            let proof = sp1_proof_with_public_values
                .proof
                .try_as_groth_16()
                .unwrap();
            (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
        }
        ProofMode::Plonk => {
            let proof = sp1_proof_with_public_values.proof.try_as_plonk().unwrap();
            (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
        }
        _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
    };

    // log(&format!("Proof: {:?}", raw_proof));
    // log(&format!("Public inputs: {:?}", public_inputs));

    // Convert public inputs to byte representations
    let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10)
        .unwrap()
        .to_bytes_be();
    let committed_values_digest = BigUint::from_str_radix(&public_inputs[1], 10)
        .unwrap()
        .to_bytes_be();

    let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest = Fr::from_slice(&committed_values_digest)
        .expect("Unable to read committed_values_digest");

    // log(&format!("vkey_hash: {:?}", vkey_hash));
    // log(&format!("committed_values_digest: {:?}", committed_values_digest));

    // Read VK from the appropriate binary
    let vk_bytes = match method {
        ProofMode::Groth16 => GROTH16_VK_BYTES,
        ProofMode::Plonk => PLONK_VK_BYTES,
    };

    // Call the appropriate verification function based on the method
    match method {
        ProofMode::Groth16 => verify_groth16_wasm(&raw_proof, &vk_bytes,  &[vkey_hash, committed_values_digest]),
        ProofMode::Plonk => verify_plonk_wasm(&raw_proof, &vk_bytes, &[vkey_hash, committed_values_digest]),
        _ => Err(JsValue::from_str("Invalid proof mode")),
    }
}
