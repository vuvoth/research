use halo2curves::pasta::pallas;
use halo2_gadgets::poseidon::primitives::{P128Pow5T3, Hash, ConstantLength};

fn main() {
    let message = [pallas::Base::from(6), pallas::Base::from(42)];
    let hasher = Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init();
    let result = hasher.hash(message);
    println!("{:#?}", result);
}
