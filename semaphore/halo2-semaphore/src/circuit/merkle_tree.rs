use halo2curves::FieldExt;
use poseidon::Spec;
use transcript::{
    halo2::{
        circuit::{SimpleFloorPlanner, Value},
        plonk::Circuit,
    },
    maingate::{MainGate, MainGateConfig, MainGateInstructions, RegionCtx},
    HasherChip,
};

#[derive(Clone)]
pub struct MerkleTreeCircuitConfig {
    pub config: MainGateConfig,
}

#[derive(Clone, Debug)]
pub struct MerkleTreeCircuit<F: FieldExt> {
    pub merkle_proof: Vec<Value<F>>,
    pub merkle_path: Vec<Value<F>>,
    pub leaf_node: Value<F>,
    pub hash_root: F,
}

impl<F: FieldExt> Circuit<F> for MerkleTreeCircuit<F> {
    type Config = MerkleTreeCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut transcript::halo2::plonk::ConstraintSystem<F>) -> Self::Config {
        let config = MainGate::configure(meta);
        MerkleTreeCircuitConfig { config }
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl transcript::halo2::circuit::Layouter<F>,
    ) -> Result<(), transcript::halo2::plonk::Error> {
        let config = config.config;
        let main_gate = MainGate::<F>::new(config.clone());

        // TODO: Check the size of merkle_path and merkle_proof is equal
        let hash_root = layouter.assign_region(
            || "",
            |region| {
                let mut ctx = RegionCtx::new(region, 0);
                let spec = Spec::<F, 3, 2>::new(8, 57);
                let mut hasher_chip = HasherChip::<F, 0, 0, 3, 2>::new(&mut ctx, &spec, &config)?;

                let mut hash_root = main_gate.assign_value(&mut ctx, self.leaf_node)?;

                for (id, hash_value) in self.merkle_proof.iter().enumerate() {
                    let select = main_gate.assign_value(&mut ctx, self.merkle_path[id])?;
                    let hash_cell = main_gate.assign_value(&mut ctx, *hash_value)?;

                    let left_child = main_gate.select(&mut ctx, &hash_root, &hash_cell, &select)?;
                    let right_child =
                        main_gate.select(&mut ctx, &hash_cell, &hash_root, &select)?;

                    hasher_chip.update(&[left_child, right_child]);
                    hash_root = hasher_chip.hash(&mut ctx)?;
                }

                Ok(hash_root)
            },
        )?;

        main_gate.expose_public(layouter, hash_root, 0)
    }
}

#[cfg(test)]
mod tests {
    use halo2curves::bn256::Fr;
    use transcript::{halo2::circuit::Value, maingate::mock_prover_verify};

    use super::MerkleTreeCircuit;

    #[test]
    fn test_circuit() {
        let mut leaf = Fr::from(123);
        let mut merkle_proof = Vec::new();
        let mut hasher = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);

        for value in 0..5 {
            hasher.update(&[leaf, Fr::from(value)]);
            leaf = hasher.squeeze();
            merkle_proof.push(Fr::from(value));
        }

        let circuit = MerkleTreeCircuit {
            leaf_node: Value::known(Fr::from(123)),
            merkle_path: (0..5).map(|_| Value::known(Fr::from(1))).collect(),
            hash_root: leaf,
            merkle_proof: merkle_proof.iter().map(|v| Value::known(*v)).collect(),
        };

        // use plotters::prelude::*;
        // let root = BitMapBackend::new("./target/semaphore.png", (1024, 768)).into_drawing_area();
        // root.fill(&WHITE).unwrap();
        // let root = root.titled("Semaphore", ("sans-serif", 60)).unwrap();

        // halo2_proofs::dev::CircuitLayout::default()
        //     // .show_labels(false)
        //     // Render the circuit onto your area!
        //     // The first argument is the size parameter for the circuit.
        //     .render(15, &circuit, &root)
        //     .unwrap();
        assert_eq!(mock_prover_verify(&circuit, vec![vec![circuit.hash_root]]), Ok(()));
    }
}
