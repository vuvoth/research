
mod snark;


#[cfg(test)]
mod tests {
    use std::vec;

    use halo2_proofs::{circuit::Value};
    use halo2curves::bn256::Fr;

    use crate::circuit::merkle_tree::MerkleTreeCircuit;

    use super::snark::*;


    #[test]
    fn test_snark_verifier() {
        let mut leaf = Fr::from(123);
        let mut merkle_proof = Vec::new();
        let mut hasher = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);

        for value in 0..5 {
            hasher.update(&[leaf, Fr::from(value)]);
            leaf = hasher.squeeze();
            merkle_proof.push(Fr::from(value));
        }

        let my_circuit = MerkleTreeCircuit {
            leaf_node: Value::known(Fr::from(123)),
            merkle_path: (0..5).map(|_| Value::known(Fr::from(1))).collect(),
            hash_root: leaf,
            merkle_proof: merkle_proof.iter().map(|v| Value::known(*v)).collect(),
        };


        let params =MyProver::gen_srs(14);
        
        let instances = vec![vec![my_circuit.hash_root]];

        let pk = MyProver::gen_pk(&params, &my_circuit);
        let contract_opcodes = MyProver::verify_smart_contact_opcode(&params, pk.get_vk(), vec![1]);
        let proof = MyProver::gen_proof(&params, &pk, my_circuit.clone(), instances.clone());
        let verify = MyProver::evm_verify(contract_opcodes, instances, proof);
        println!("{}", verify);
        assert!(verify);
    }
}
