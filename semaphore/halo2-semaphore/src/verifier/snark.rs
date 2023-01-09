use std::rc::Rc;

use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use itertools::Itertools;

use rand::{rngs::OsRng};
use snark_verifier::{
    loader::evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

pub trait SnarkProver {
    fn gen_srs(k: u32) -> ParamsKZG<Bn256>;
    fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine>;
    fn verify_smart_contact_opcode(
        params: &ParamsKZG<Bn256>,
        vk: &VerifyingKey<G1Affine>,
        num_instance: Vec<usize>,
    ) -> Vec<u8>;
    fn gen_proof<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        circuit: C,
        instances: Vec<Vec<Fr>>,
    ) -> Vec<u8>;
    fn evm_verify(contract_opcodes: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> bool;
}

pub struct MyProver;

impl SnarkProver for MyProver {
    fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
        ParamsKZG::<Bn256>::setup(k, OsRng)
    }

    fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
        let vk = keygen_vk(params, circuit).unwrap();
        keygen_pk(params, vk, circuit).unwrap()
    }

    fn gen_proof<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        circuit: C,
        instances: Vec<Vec<Fr>>,
    ) -> Vec<u8> {
        MockProver::run(params.k(), &circuit, instances.clone())
            .unwrap()
            .assert_satisfied();

        let instances = instances
            .iter()
            .map(|instances| instances.as_slice())
            .collect_vec();
        let proof = {
            let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverGWC<_>,
                _,
                _,
                EvmTranscript<_, _, _, _>,
                _,
            >(
                params,
                pk,
                &[circuit],
                &[instances.as_slice()],
                OsRng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };

        let accept = {
            let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
            VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                    params.verifier_params(),
                    pk.get_vk(),
                    AccumulatorStrategy::new(params.verifier_params()),
                    &[instances.as_slice()],
                    &mut transcript,
                )
                .unwrap(),
            )
        };
        assert!(accept);

        proof
    }

    fn verify_smart_contact_opcode(
        params: &ParamsKZG<Bn256>,
        vk: &VerifyingKey<G1Affine>,
        num_instance: Vec<usize>,
    ) -> Vec<u8> {
        let protocol = compile(
            params,
            vk,
            Config::kzg().with_num_instance(num_instance.clone()),
        );
        let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

        let loader = EvmLoader::new::<Fq, Fr>();
        let protocol = protocol.loaded(&loader);
        let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

        let instances = transcript.load_instances(num_instance);
        let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
        PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

        evm::compile_yul(&loader.yul_code())
    }

    fn evm_verify(contract_opcodes: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> bool {
        let calldata = encode_calldata(&instances, &proof);
        let success = {
            let mut evm = ExecutorBuilder::default()
                .with_gas_limit(u64::MAX.into())
                .build();

            let caller = Address::from_low_u64_be(0xfe);
            let verifier = evm
                .deploy(caller, contract_opcodes.into(), 0.into())
                .address
                .unwrap();
            let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

            dbg!(result.gas_used);

            !result.reverted
        };
        success
    }
}
