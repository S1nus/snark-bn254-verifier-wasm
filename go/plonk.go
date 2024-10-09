package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk" // or "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
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
	var circuit cubic.Circuit

	// compile a circuit
	scs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Error compiling circuit: %v\n", err)
		return
	}

	// Run the dummy setup.
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		fmt.Printf("Error creating SRS: %v\n", err)
		return
	}

	_, vk, err := plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		fmt.Printf("Error in Plonk setup: %v\n", err)
		return
	}

	// Save verification key
	err = saveVerificationKey(vk, "plonk_vk.bin")
	if err != nil {
		fmt.Printf("Error saving verification key: %v\n", err)
		return
	}

	fmt.Println("Verification key saved successfully.")
}
