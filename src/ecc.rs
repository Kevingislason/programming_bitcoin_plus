//Adapted from Jimmy Song's Programming Bitcoin library
//https://github.com/jimmysong/programmingbitcoin/

//Boring imports
use core::convert::TryInto;
use core::fmt;
use core::ops;
extern crate num;
use num::bigint::BigInt;
use num::bigint::Sign::Plus;
use num::pow::pow;
use num_traits::identities::{One, Zero};
extern crate hex;

//Hash stuff
use sha2::{Digest, Sha256};

//Used for generating a pseudo-random K to sign transactions
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

//Some convenience functions
use crate::ecc_helpers::{encode_base58_checksum, hash_160};

//This "lazy static" macro lets us use structs sort of like constants
use lazy_static;
#[macro_use]
lazy_static! {
  //SECP256K1 curve is over  -->  y**2 == x**3 + Ax + B --> y**2 == x**3 + 7
  static ref A: S256FieldElement = S256FieldElement::new(BigInt::zero());
  static ref B: S256FieldElement = S256FieldElement::new(BigInt::from(7u8));

  //The SECP256K1 prime
  static ref P: BigInt = BigInt::parse_bytes(
    b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
  .unwrap();

  //The SECP256K1 generator point
  static ref G: S256Point = S256Point::from_hex(
    b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

  //The order of the generator point
  static ref N: BigInt = BigInt::parse_bytes(
    b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
    .unwrap();

}

#[derive(PartialEq, Debug, Clone)]
pub struct S256FieldElement {
  pub num: BigInt,
  prime: BigInt,
}

impl S256FieldElement {
  pub fn new(num: BigInt) -> S256FieldElement {
    let prime = P.clone();
    if num >= prime || num < BigInt::zero() {
      panic!("Num {} not in field range 0 to {}", num, P.clone())
    }
    return S256FieldElement { prime, num };
  }

  pub fn zero() -> S256FieldElement {
    S256FieldElement::new(BigInt::zero())
  }

  //My code here is simpler than the code in Jimmy Song's book because I'm never
  //dealing with cases where an exponent is larger than the SECP prime, or is negative
  fn pow(&self, exponent: u8) -> S256FieldElement {
    let exponent = BigInt::from(exponent);
    let num = pow_mod(&self.num, &exponent, &self.prime);
    return S256FieldElement {
      num: num,
      prime: P.clone(),
    };
  }
}

fn pow_mod(base: &BigInt, power: &BigInt, modulo: &BigInt) -> BigInt {
  let mut power = power.clone();
  let mut result = BigInt::one();
  let mut base = base % modulo;
  while power > BigInt::zero() {
    if &power % BigInt::from(2u8) == BigInt::one() {
      result = result * &base % modulo;
      power = power - &BigInt::one();
    }
    power = power / BigInt::from(2u8);
    base = &base * &base % modulo;
  }
  result
}

impl From<u8> for S256FieldElement {
  fn from(num: u8) -> S256FieldElement {
    S256FieldElement::new(BigInt::from(num))
  }
}

impl fmt::Display for S256FieldElement {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "num: {}, prime: {}",
      &self.num.to_str_radix(16),
      &self.prime.to_str_radix(16)
    )
  }
}

//Operator overrides for S256FieldElement (+, -, *, /)
//Using a convenient macro from https://docs.rs/impl_ops/0.1.1/impl_ops/

impl_op_ex!(+ |a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
      S256FieldElement {
      num: (&a.num + &b.num) % &a.prime,
      prime: P.clone(),
    }
  });

impl_op_ex!(
  -|a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
    let mut result = (&a.num - &b.num) % &a.prime;

    //Rust's "mod" can return negative numbers (unlike e.g. Python's mod)
    //e.g. -11 % 5 = -1 in rust, but we want it to equal 4 instead
    if result < BigInt::zero() {
      result = result + &a.prime;
    }
    assert!(result >= BigInt::zero());

    S256FieldElement {
      num: result,
      prime: P.clone(),
    }
  }
);

impl_op_ex!(
  *|a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
    S256FieldElement {
      num: (&a.num * &b.num) % &a.prime,
      prime: P.clone(),
    }
  }
);

impl_op_ex!(
  / |a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
 let num = &a.num * pow_mod(&b.num, &(&a.prime - 2), &a.prime) % &a.prime;
    S256FieldElement {
      num: num,
      prime: P.clone(),
    }
  }
);

#[derive(PartialEq, Debug, Clone)]
pub struct S256Point {
  x: Option<S256FieldElement>,
  y: Option<S256FieldElement>,
}

//A point on the SECP256K1 curve
impl S256Point {
  pub fn new(x: Option<S256FieldElement>, y: Option<S256FieldElement>) -> S256Point {
    match (x, y) {
      //point at infinity
      (None, None) => return S256Point { x: None, y: None },
      (Some(x), None) => panic!("({}, None) is not on the SECP256K1 curve", x),
      (None, Some(y)) => panic!("(None, {}) is not on the SECP256K1 curve", y),
      (Some(x), Some(y)) => {
        if y.pow(2) != x.pow(3) + B.clone() {
          panic!("({}, {}) is not on the SECP256k1 curve", x, y)
        }
        return S256Point {
          x: Some(x),
          y: Some(y),
        };
      }
    }
  }

  pub fn point_at_infinity() -> S256Point {
    S256Point::new(None, None)
  }

  pub fn from_hex(x: &[u8], y: &[u8]) -> S256Point {
    let x = S256FieldElement::new(BigInt::parse_bytes(x, 16).unwrap());
    let y = S256FieldElement::new(BigInt::parse_bytes(y, 16).unwrap());
    S256Point::new(Some(x), Some(y))
  }

  //The math behind ECC is too complicated to fully explain in comments
  //See https://github.com/jimmysong/programmingbitcoin/blob/master/ch03.asciidoc
  pub fn verify_signatture(&self, z: &BigInt, signature: &Signature) -> bool {
    let s_inverse = pow_mod(&signature.s, &(N.clone() - &BigInt::from(2)), &N.clone());
    let u = z * &s_inverse % N.clone();
    let v = &signature.r * s_inverse % N.clone();
    let total = G.clone() * u + self * v;
    match total.x {
      None => false,
      Some(field_element) => field_element.num == signature.r,
    }
  }

  //SEC serialization format for Bitcoin SECP256K1 addresses
  pub fn sec(&self, compressed: bool) -> Vec<u8> {
    let mut result = vec![];

    let x = match &self.x {
      None => panic!("Can't serialize the point at infinity"),
      Some(field_element) => &field_element.num,
    };
    let y = match &self.y {
      None => panic!("Can't serialize the point at infinity"),
      Some(field_element) => &field_element.num,
    };
    let mut x_bytes = fill_to_32_bytes(x.to_bytes_be().1).to_vec();
    let mut y_bytes = fill_to_32_bytes(y.to_bytes_be().1).to_vec();

    if compressed {
      if y % BigInt::from(2) == BigInt::zero() {
        result.push(2);
        result.append(&mut x_bytes);
      } else {
        result.push(3);
        result.append(&mut x_bytes);
      }
      return result;
    } else {
      result.push(4);
      result.append(&mut x_bytes);
      result.append(&mut y_bytes);
      return result;
    }
  }

  fn hash_160(&self, compressed: bool) -> Vec<u8> {
    return hash_160(self.sec(compressed));
  }

  pub fn address(&self, compressed: bool, testnet: bool) -> String {
    let mut h160 = self.hash_160(compressed);
    let mut result = vec![];
    let mut prefix = vec![];
    if testnet {
      prefix = vec![0x6f];
    } else {
      prefix = vec![0x00];
    }
    result.append(&mut prefix);
    result.append(&mut h160);
    encode_base58_checksum(result)
  }
}

impl fmt::Display for S256Point {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match (&self.x, &self.y) {
      //point at infinity
      (None, None) => write!(f, "Point at infinity"),
      (Some(x), Some(y)) => write!(
        f,
        "x={}, y={}",
        x.num.to_str_radix(16),
        y.num.to_str_radix(16)
      ),
      (None, _) => panic!(
        "(None, {}) is not on the SECP256K1 curve",
        self.y.clone().unwrap().num.to_str_radix(16)
      ),
      (_, None) => panic!(
        "({}, None) is not on the SECP256K1 curve",
        self.y.clone().unwrap().num.to_str_radix(16)
      ),
    }
  }
}

//Operator overrides for S256Point (+, -, *, /)
//Using a convenient macro from https://docs.rs/impl_ops/0.1.1/impl_ops/

impl_op_ex!(
  +|a: &S256Point,  b: &S256Point| -> S256Point {
    match ((&a.x, &a.y), (&b.x, &b.y)) {
      //Case 0.0: self is the point at infinity, return other
      ((None, None), _) => return b.clone(),
      //Case 0.1: other is the point at infinity, return self
      (_, (None, None)) => return a.clone(),

      ((Some(x1), Some(y1)), (Some(x2), Some(y2))) => {
        //Case 1: self.x == other.x, self.y != other.y
        //Result is point at infinity
        if x1 == x2 && y1 != y2 {
          return S256Point::point_at_infinity();
        }
        //Case 2: self.x ≠ other.x
        //Formula (x3,y3)==(x1,y1)+(x2,y2)
        //s=(y2-y1)/(x2-x1)
        //x3=s**2-x1-x2
        //y3=s*(x1-x3)-y1
        else if x1 != x2 {
          let s = (y2 - y1) / (x2 - x1);
          let x = s.pow(2) - x1 - x2;
          let y = s * (x1 - &x) - y1;
          return S256Point::new(Some(x), Some(y));
        }
        //Case 3: if we are tangent to the vertical line,
        //we return the point at infinity
        //I'm not actually sure that such a point exists on the SECP256k1 field tbh...
        else if &a == &b && y1 == &S256FieldElement::zero() {
          return S256Point::point_at_infinity();
        }
        // Case 4: self == other
        // Formula (x3,y3)=(x1,y1)+(x1,y1)
        // s=(3*x1**2+a)/(2*y1)
        // x3=s**2-2*x1
        // y3=s*(x1-x3)-y1
        else {
          let s = S256FieldElement::from(3) * x1.pow(2) / (S256FieldElement::from(2) * y1);
          let x = s.pow(2) - S256FieldElement::from(2) * x1;
          let y = s * (x1 - &x) - y1;
          return S256Point::new(Some(x), Some(y));
        }
      }
      _ => panic!("At least one of the S256K1 points you tried to add is INVALID"),
    }
  }
);

impl_op_ex!(*|a: &S256Point, b: &BigInt| -> S256Point {
  let mut coefficient = b % N.clone();
  let mut current = a.to_owned();
  let mut result = S256Point::point_at_infinity();
  while &coefficient > &BigInt::zero() {
    if &coefficient & BigInt::from(1) == BigInt::from(1) {
      result = result + &current;
    }
    current = &current + &current;
    coefficient = coefficient >> 1;
  }
  result
});

#[derive(Debug)]
pub struct Signature {
  r: BigInt,
  s: BigInt,
}

impl fmt::Display for Signature {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "num: {}, prime: {}",
      &self.r.to_str_radix(16),
      &self.s.to_str_radix(16)
    )
  }
}

impl Signature {
  //Serialize signature in DER format
  pub fn der(&self) -> Vec<u8> {
    let mut rbin = self.r.to_bytes_be().1;
    if rbin[0] & 0x80 != 0 {
      let mut rbin_without_prefix = rbin.clone();
      rbin = vec![0];
      rbin.append(&mut rbin_without_prefix);
    }
    let mut result_body = vec![2u8, rbin.len() as u8];
    result_body.append(&mut rbin);

    let mut sbin = self.s.to_bytes_be().1;
    if sbin[0] & 0x80 != 0 {
      let mut sbin_without_prefix = sbin.clone();
      sbin = vec![0];
      sbin.append(&mut sbin_without_prefix);
    }
    let mut serialized_s = vec![2u8, sbin.len() as u8];
    serialized_s.append(&mut sbin);
    result_body.append(&mut serialized_s);

    let mut result = vec![48u8, result_body.len() as u8];
    result.append(&mut result_body);
    result
  }
}

pub struct PrivateKey {
  secret: BigInt,
  pub point: S256Point,
}

impl PrivateKey {
  pub fn new(secret: BigInt) -> PrivateKey {
    let point = G.clone() * &secret;
    PrivateKey { secret, point }
  }

  pub fn sign(&self, z: &BigInt) -> Signature {
    let k = self.deterministic_k(z);
    let r = (G.clone() * &k).x.unwrap().num;
    let k_inverse = pow_mod(&k, &(N.clone() - BigInt::from(2)), &N.clone());
    let mut s = (z + &r * &self.secret) * k_inverse % N.clone();
    if s > N.clone() / BigInt::from(2) {
      s = N.clone() - s;
    }
    Signature { r, s }
  }

  pub fn wif(&self, compressed: bool, testnet: bool) -> String {
    let mut secret_bytes = fill_to_32_bytes(self.secret.to_bytes_be().1).to_vec();
    let mut prefix = match testnet {
      true => vec![0xef],
      false => vec![0x80],
    };
    let mut suffix = match compressed {
      true => vec![0x01],
      false => vec![],
    };
    let mut unencoded = vec![];
    unencoded.append(&mut prefix);
    unencoded.append(&mut secret_bytes);
    unencoded.append(&mut suffix);
    encode_base58_checksum(unencoded)
  }

  //looks a lot nicer in Python
  fn deterministic_k(&self, z: &BigInt) -> BigInt {
    let mut k: [u8; 32] = [0; 32];
    let mut v: [u8; 32] = [1; 32];
    let mut z = z.clone();
    if z > N.clone() {
      z = z - N.clone();
    }
    let z_bytes = fill_to_32_bytes(z.to_bytes_be().1);
    let secret_bytes = fill_to_32_bytes(self.secret.to_bytes_be().1);

    let k_message = construct_long_hmac_message(vec![&v, &[0u8], &secret_bytes, &z_bytes]);
    k = get_hmac_result(&k_message, &k);

    v = get_hmac_result(&v, &k);

    let k_message = construct_long_hmac_message(vec![&v, &[1u8], &secret_bytes, &z_bytes]);
    k = get_hmac_result(&k_message, &k);

    v = get_hmac_result(&v, &k);

    loop {
      v = get_hmac_result(&v, &k);
      let candidate = BigInt::from_bytes_be(Plus, &v);
      if candidate >= BigInt::from(1) && candidate < N.clone() {
        return candidate;
      }
      let k_message = construct_short_hmac_message(vec![&v, &[0u8]]);
      k = get_hmac_result(&k_message, &k);

      v = get_hmac_result(&v, &k);
    }
  }
}

//helper function for deterministic_k
fn get_hmac_result(hmac_message: &[u8], hmac_varkey: &[u8; 32]) -> [u8; 32] {
  let mut mac = HmacSha256::new_varkey(hmac_varkey).expect("HMAC can take key of any size");
  mac.input(&hmac_message[..]);
  let result = mac.result().code();
  result
    .as_slice()
    .try_into()
    .expect("Couldn't convert HMAC result into array")
}

//helper function for deterministic_k
fn construct_long_hmac_message(components: Vec<&[u8]>) -> [u8; 97] {
  let mut message_arr = [0; 97];
  let mut i = 0;
  for component in components {
    for byte in component {
      message_arr[i] = byte.clone();
      i += 1;
    }
  }
  assert_eq!(i, 97);
  return message_arr;
}

//helper function for deterministic_k
fn construct_short_hmac_message(components: Vec<&[u8]>) -> [u8; 33] {
  let mut message_arr = [0; 33];
  let mut i = 0;
  for component in components {
    for byte in component {
      message_arr[i] = byte.clone();
      i += 1;
    }
  }
  assert_eq!(i, 33);
  return message_arr;
}

//say out private key secret is 1
//Rust represents it as [1u8]
//But to calculate deterministic_k, we need 32 bytes total
//e.g. [0, 0, 0, 0, 0, ... 1]
fn fill_to_32_bytes(mut vector: Vec<u8>) -> [u8; 32] {
  let mut result: [u8; 32] = [0; 32];
  let offset = 32 - vector.len();
  for i in 0..vector.len() {
    result[i + offset] = vector[i];
  }
  result
}

#[test]
fn test_order() {
  let point = G.clone() * N.clone();
  assert_eq!(point, S256Point::point_at_infinity())
}

#[test]
fn test_add_points() {
  //Case 0.0: self is the point at infinity, return other
  let point1 = S256Point::point_at_infinity();
  let point2 = S256Point::from_hex(
    b"2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
    b"2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959",
  );
  assert_eq!(point1 + &point2, point2);

  //silly edge case: point at infinity + point at infinity
  let point1 = S256Point::point_at_infinity();
  let point2 = S256Point::point_at_infinity();
  assert_eq!(point1 + point2, S256Point::point_at_infinity());

  //Case 0.1: other is the point at infinity, return self
  let point1 = S256Point::from_hex(
    b"E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13",
    b"AE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D",
  );
  let point2 = S256Point::point_at_infinity();
  assert_eq!(&point1 + point2, point1);

  //Case 1: self.x == other.x, self.y != other.y
  let point1 = S256Point::from_hex(
    b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
  );
  let point2 = S256Point::from_hex(
    b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    b"b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
  );
  assert_eq!(point1 + point2, S256Point::point_at_infinity());

  //Case 2: self.x ≠ other.x
  let point1 = S256Point::from_hex(
    b"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
    b"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
  );
  let point2 = S256Point::from_hex(
    b"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    b"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
  );
  let point3 = S256Point::from_hex(
    b"2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
    b"D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6",
  );
  assert_eq!(point1 + point2, point3);

  //Case 3: I don't think any cases exist for S256K1

  //Case 4: self == other
  let point1 = G.clone();
  let point2 = G.clone();
  let point3 = S256Point::from_hex(
    b"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
    b"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
  );
  assert_eq!(&point1 + &point2, point3);
}

#[test]
fn test_multiply_point_by_scalar() {
  //Stuipd edge case
  assert_eq!(
    S256Point::point_at_infinity() * BigInt::from(100),
    S256Point::point_at_infinity()
  );

  let generator_point = G.clone();

  //G * 2
  let result = S256Point::from_hex(
    b"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
    b"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
  );
  assert_eq!(&generator_point * BigInt::from(2), result);

  //G * 1485
  let result = S256Point::from_hex(
    b"c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda",
    b"7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55",
  );

  //G * 2^128
  assert_eq!(&generator_point * BigInt::from(1485), result);

  let result = S256Point::from_hex(
    b"8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
    b"662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82",
  );
  assert_eq!(&generator_point * pow(BigInt::from(2), 128), result);

  //G * (2^240 + 2^31)
  let result = S256Point::from_hex(
    b"9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116",
    b"10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053",
  );
  assert_eq!(
    generator_point * (pow(BigInt::from(2), 240) + (pow(BigInt::from(2), 31))),
    result
  );
}

#[test]
fn test_deterministic_k() {
  let my_privkey = PrivateKey::new(BigInt::from(1));
  let mut sha256 = Sha256::new();
  sha256.input(b"1");
  let z: [u8; 32] = sha256.result().into();
  let z: BigInt = BigInt::from_bytes_be(Plus, &z);
  let k = my_privkey.deterministic_k(&z);

  let expected_result = BigInt::parse_bytes(
    b"f24af0377e1b27fbebae63b3bec9b249b5bb0b0ba975896dbf35d79b189d19d3",
    16,
  )
  .unwrap();
  assert_eq!(k, expected_result);
}

#[test]
fn test_verify_signature() {
  let point = S256Point::from_hex(
    b"887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c",
    b"61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
  );
  let z = BigInt::parse_bytes(
    b"ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60",
    16,
  )
  .unwrap();
  let r = BigInt::parse_bytes(
    b"ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395",
    16,
  )
  .unwrap();
  let s = BigInt::parse_bytes(
    b"68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
    16,
  )
  .unwrap();
  assert!(point.verify_signatture(&z, &Signature { r, s }) == true)
}

#[test]
fn test_sign() {
  let private_key = PrivateKey::new(BigInt::from(1234567890)); //chosen arbitrarily
  let z = BigInt::from(987654321); //chosen arbitrarily
  let signature = private_key.sign(&z);
  assert!(private_key.point.verify_signatture(&z, &signature));
}

#[test]
fn test_serialize_sec() {
  let coefficient = BigInt::from(pow(999, 3));
  let uncompressed = "049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9";
  let compressed = "039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5";
  let point = G.clone() * coefficient;
  assert_eq!(hex::decode(uncompressed).unwrap(), point.sec(false));
  assert_eq!(hex::decode(compressed).unwrap(), point.sec(true));

  let coefficient = BigInt::from(123);
  let uncompressed = "04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b";
  let compressed = "03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5";
  let point = G.clone() * coefficient;
  assert_eq!(hex::decode(uncompressed).unwrap(), point.sec(false));
  assert_eq!(hex::decode(compressed).unwrap(), point.sec(true));

  let coefficient = BigInt::from(42424242);
  let uncompressed = "04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3";
  let compressed = "03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e";
  let point = G.clone() * coefficient;
  assert_eq!(hex::decode(uncompressed).unwrap(), point.sec(false));
  assert_eq!(hex::decode(compressed).unwrap(), point.sec(true)); //hmm...
}

#[test]
fn test_serialize_der() {
  let private_key = PrivateKey::new(BigInt::from(1234567890)); //chosen arbitrarily
  let z = BigInt::from(987654321); //chosen arbitrarily
  let signature = private_key.sign(&z);
  let expected_result = "3045022100b5fb2e0b3a79dacbb56b08d7b13c9417c635dd6083201b19f6caba2694583741022043e6313219e0154f23373681d9c39239669163f0bbab5ca7198a9bbc9e33ade2";
  assert_eq!(expected_result, hex::encode(signature.der()));

  let private_key = PrivateKey::new(BigInt::from(99999)); //chosen arbitrarily
  let z = BigInt::from(77777); //chosen arbitrarily
  let signature = private_key.sign(&z);
  let expected_result = "304402201c65f69096aba3df70b37b5778d7f6e6376672f859e13ddcd3ddb17f0aa8c84802202294cd6189ac8451137f811e2c0fa2a3fe6a737d472c21d94a4ea9558c9b5be7";
  assert_eq!(expected_result, hex::encode(signature.der()));

  let private_key = PrivateKey::new(BigInt::from(19891)); //chosen arbitrarily
  let z = BigInt::from(13868); //chosen arbitrarily
  let signature = private_key.sign(&z);
  let expected_result = "3045022100998c323c9453c385e73c569a1770e35a4e05241acbe8123146e70c1e6896968702202c8ec157da679532be68f95453a2dac37902e6f52f7cc073c6bc19e8789d235b";
  assert_eq!(expected_result, hex::encode(signature.der()));
}

#[test]
fn test_address() {
  let secret = BigInt::from(pow(BigInt::from(888), 3));
  let mainnet_address = String::from("148dY81A9BmdpMhvYEVznrM45kWN32vSCN");
  let testnet_address = String::from("mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP");
  let point = G.clone() * secret;
  assert_eq!(point.address(true, false), mainnet_address);
  assert_eq!(point.address(true, true), testnet_address);

  let secret = BigInt::from(321);
  let mainnet_address = String::from("1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj");
  let testnet_address = String::from("mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP");
  let point = G.clone() * secret;
  assert_eq!(point.address(false, false), mainnet_address);
  assert_eq!(point.address(false, true), testnet_address);

  let secret = BigInt::from(4242424242u64);
  let mainnet_address = String::from("1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb");
  let testnet_address = String::from("mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s");
  let point = G.clone() * secret;
  assert_eq!(point.address(false, false), mainnet_address);
  assert_eq!(point.address(false, true), testnet_address)
}

#[test]
fn test_wif() {
  let pk = PrivateKey::new(pow(BigInt::from(2), 256) - pow(BigInt::from(2), 199));
  let expected = String::from("L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC");
  assert_eq!(pk.wif(true, false), expected);

  let pk = PrivateKey::new(pow(BigInt::from(2), 256) - pow(BigInt::from(2), 201));
  let expected = "93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn";
  assert_eq!(pk.wif(false, true), expected);

  let pk = PrivateKey::new(
    BigInt::parse_bytes(
      b"0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d",
      16,
    )
    .unwrap(),
  );
  let expected = "5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty";
  assert_eq!(pk.wif(false, false), expected);

  let pk = PrivateKey::new(
    BigInt::parse_bytes(
      b"1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f",
      16,
    )
    .unwrap(),
  );
  let expected = "cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg";
  assert_eq!(pk.wif(true, true), expected);
}

//Things that would make this code better:
//1: replace BigInts with BigUInts?
//2. Add tests for S256FieldElement
//3. See if I can avoid invoking ".code" in get_hmac_result (apparently insecure?)

//todo: Parse for point and sig
