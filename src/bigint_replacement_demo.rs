use bigint::{U256, U512};


#[test]
pub fn test_U256_as_bigint_substitute() {
  let max_int = U256::max_value();
  let a = U512::from(max_int.clone());
  let b = a.clone();

  println!("{}", a * b);

}
