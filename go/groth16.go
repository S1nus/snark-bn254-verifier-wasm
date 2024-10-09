package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"

	// "github.com/consensys/gnark/backend/plonk" // or "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func saveVerificationKey(vk plonk.VerifyingKey, filename string) error {
	vkFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create verification key file: %w", err)
	}
	defer vkFile.Close()

	_, err = vk.WriteTo(vkFile)
	if err != nil {
		return fmt.Errorf("failed to write verification key: %w", err)
	}

	return nil
}

func saveProof(proof plonk.Proof, filename string) error {
	proofFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create proof file: %w", err)
	}
	defer proofFile.Close()

	_, err = proof.WriteTo(proofFile)
	if err != nil {
		return fmt.Errorf("failed to write proof: %w", err)
	}

	return nil
}

func main() {
	// Assume vk and proof are already generated
	var circuit cubic.Circuit

	// compile a circuit
	_r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// R1CS implements io.WriterTo and io.ReaderFrom
	var buf bytes.Buffer
	_, _ = _r1cs.WriteTo(&buf)

	// gnark objects (R1CS, ProvingKey, VerifyingKey, Proof) must be instantiated like so:
	newR1CS := groth16.NewCS(ecc.BN254)
	_, _ = newR1CS.ReadFrom(&buf)

	// setup
	_, vk, _ := groth16.Setup(_r1cs)

	// Save verification key
	err := saveVerificationKey(vk, "groth16_vk.bin")
	if err != nil {
		fmt.Printf("Error saving verification key: %v\n", err)
		return
	}

	fmt.Println("Verification key and proof saved successfully.")
}
