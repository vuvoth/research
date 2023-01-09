
mod snark;
mod aggregate;

#[cfg(test)]
mod tests {
    use std::vec;

    use halo2_proofs::{circuit::Value};
    use halo2_curves::bn256::Fr;

    use crate::circuit::merkle_tree::{MerkleTreeCircuit, gen_merkle_circuit_data};

    use super::snark::*;

    #[test]
    fn test_snark_verifier() {    
        let my_circuit = gen_merkle_circuit_data(5);

        let params =MyProver::gen_srs(14);
        
        let instances = vec![vec![my_circuit.hash_root]];

        let pk = MyProver::gen_pk(&params, &my_circuit);
        let contract_opcodes = MyProver::verify_smart_contact_opcode(&params, pk.get_vk(), vec![1]);
        let proof = MyProver::gen_proof(&params, &pk, my_circuit.clone(), instances.clone());
        let verify = MyProver::evm_verify(contract_opcodes, instances, proof);
        assert!(verify);
    }
}
