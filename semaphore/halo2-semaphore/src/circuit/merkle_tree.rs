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
    pub leaf_node: Value<F>,
    pub hash_root: Value<F>,
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

        layouter.assign_region(
            || "",
            |region| {
                let main_gate = MainGate::new(config.clone());

                let mut ctx = RegionCtx::new(region, 0);
                let spec = Spec::<F, 3, 2>::new(8, 57);
                let mut hasher_chip = HasherChip::<F, 0, 0, 3, 2>::new(&mut ctx, &spec, &config)?;

                let mut hash_value = main_gate.assign_value(&mut ctx, self.leaf_node)?;

                for another_hash in self.merkle_proof.clone() {
                    let hash_cell = main_gate.assign_value(&mut ctx, another_hash)?;
                    hasher_chip.update(&[hash_value.clone(), hash_cell]);
                    hash_value = hasher_chip.hash(&mut ctx)?;
                    println!("{:?}", hash_value.value());
                }

                println!("{:?} {:?}", self.hash_root, hash_value.value());
                let root = main_gate.assign_value(&mut ctx, self.hash_root)?;

                main_gate.assert_equal(&mut ctx, &hash_value, &root)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2curves::bn256::Fr;
    use transcript::{halo2::circuit::Value, maingate::mock_prover_verify};

    use super::MerkleTreeCircuit;

    #[test]
    fn test() {
        let mut leaf = Fr::from(123);
        let mut merkle_proof = Vec::new();
        let mut hasher = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);

        for value in 0..=7 {
            hasher.update(&[leaf, Fr::from(value)]);
            leaf = hasher.squeeze();
            merkle_proof.push(Fr::from(value));
            println!("{:?}", leaf);
        }

        let circuit = MerkleTreeCircuit {
            leaf_node: Value::known(Fr::from(123)),
            hash_root: Value::known(leaf),
            merkle_proof: merkle_proof.iter().map(|v| Value::known(*v)).collect(),
        };
        assert_eq!(mock_prover_verify(&circuit, vec![vec![]]), Ok(()));
    }
}
