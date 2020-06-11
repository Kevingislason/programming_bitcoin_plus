//More or less adapted from Jimmy Song's Programming Bitcoin library
//https://github.com/jimmysong/programmingbitcoin/

//todo:  Add tests for S256FieldElement, powmod
//todo: implement public key type

extern crate hex;
extern crate num;
use crate::helpers::{encode_base58_checksum, hash_160, U256_from_hex_str};
use bigint::{U256, U512};
use core::convert::TryInto;
use core::fmt;
use hmac::{Hmac, Mac};
use num::pow::pow;
use sha2::{Digest, Sha256};
type HmacSha256 = Hmac<Sha256>;

use lazy_static;
#[macro_use]
lazy_static! {
  //SECP256K1 curve is over  -->  y**2 == x**3 + Ax + B --> y**2 == x**3 + 7
  static ref A: S256FieldElement = S256FieldElement::new(U256::zero());
  static ref B: S256FieldElement = S256FieldElement::new(U256::from(7u8));

  //The SECP256K1 prime
  static ref P: U256 = U256::from_dec_str(
    &"115792089237316195423570985008687907853269984665640564039457584007908834671663")
  .unwrap();

  //The SECP256K1 generator point
  static ref G: S256Point = S256Point::from_hex(
    &"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    &"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

  //The order of the generator point
  pub static ref N: U256 = U256::from_dec_str(
    &"115792089237316195423570985008687907852837564279074904382605163141518161494337")
    .unwrap();
}

#[derive(PartialEq, Debug, Clone)]
pub struct S256FieldElement {
  pub num: U256,
  prime: U256,
}

impl S256FieldElement {
  pub fn new(num: U256) -> S256FieldElement {
    let prime = P.clone();
    if num >= prime || num < U256::zero() {
      panic!("Num {} not in field range 0 to {}", num, P.clone())
    }
    return S256FieldElement { prime, num };
  }

  pub fn zero() -> S256FieldElement {
    S256FieldElement::new(U256::zero())
  }

  fn pow(&self, exponent: u8) -> S256FieldElement {
    let exponent = U256::from(exponent);
    let num = pow_mod(self.num.clone(), exponent.clone(), self.prime.clone());
    return S256FieldElement {
      num: num,
      prime: P.clone(),
    };
  }
}

fn pow_mod(base: U256, power: U256, modulo: U256) -> U256 {
  // Our inputs and outputs should never be greater than the max U256
  // But in the intermediary stpes, we must convert everything to to 512 to prevent overflow
  // This alone makes basiclally this whole project significantly slower
  // But there's no other way to do it that's no_std compatible
  // ...short of implementing my own no_std bigint, and I have better things to do
  let modulo = U512::from(modulo);
  let mut power = U512::from(power);
  let mut result = U512::one();
  let mut base = U512::from(base) % modulo;
  while power > U512::zero() {
    if power.clone() % U512::from(2u8) == U512::one() {
      result = result.clone() * base.clone() % modulo.clone();
      power = power - U512::one();
    }
    power = power / U512::from(2u8);
    base = base.clone().pow(U512::from(2)) % modulo;
  }
  U256::from(result)
}

impl From<u8> for S256FieldElement {
  fn from(num: u8) -> S256FieldElement {
    S256FieldElement::new(U256::from(num))
  }
}

impl fmt::Display for S256FieldElement {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let mut num_bytes = vec![0; 32];
    let mut vec_bytes = vec![0; 32];
    &self.num.to_big_endian(&mut num_bytes);
    &self.prime.to_big_endian(&mut vec_bytes);
    write!(
      f,
      "num: {}, prime: {}",
      hex::encode(num_bytes),
      hex::encode(vec_bytes)
    )
  }
}

//Operator overrides for S256FieldElement

impl_op_ex!(+ |a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
    //Convert a.num and b.num from U256 to U512 to prevent overflow when adding
    let a_num = U512::from(a.num);
    let b_num = U512::from(b.num);
    let prime = U512::from(a.prime);
    S256FieldElement {
    num: U256::from((a_num + b_num) % prime),
    prime: P.clone(),
  }
});

impl_op_ex!(
  -|a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
    let result;
    //since we are using ungined ints, we don't want to go negative here
    if a.num < b.num {
      result = a.prime.clone() - (b.num.clone() - a.num.clone());
    } else {
      result = a.num.clone() - b.num.clone();
    }

    S256FieldElement {
      num: result,
      prime: P.clone(),
    }
  }
);

impl_op_ex!(
  *|a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
    let a_num = U512::from(a.num);
    let b_num = U512::from(b.num);
    let prime = U512::from(a.prime);
    S256FieldElement {
      num: U256::from((a_num * b_num) % prime),
      prime: P.clone(),
    }
  }
);

impl_op_ex!(
  / |a: &S256FieldElement, b: &S256FieldElement| -> S256FieldElement {
  let a_num = U512::from(a.num);
  let pow_mod_expression = U512::from(
    pow_mod(b.num.clone(), a.prime.clone() - U256::from(2u8), a.prime.clone()));
  let prime = U512::from(a.prime);
  let num = a_num * pow_mod_expression % prime;
    S256FieldElement {
      num: U256::from(num),
      prime: P.clone(),
    }
  }
);

#[derive(PartialEq, Debug, Clone)]
pub struct S256Point {
  pub x: Option<S256FieldElement>,
  pub y: Option<S256FieldElement>,
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
        //convert to U512 to prevent overflow
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

  pub fn from_hex(x: &str, y: &str) -> S256Point {
    let x_bytes = hex::decode(x).unwrap();
    let y_bytes = hex::decode(y).unwrap();
    println!("x.len(): {}", x.len());
    println!("y.len(): {}", y.len());
    let x = S256FieldElement::new(U256::from_big_endian(&x_bytes));
    let y = S256FieldElement::new(U256::from_big_endian(&y_bytes));
    S256Point::new(Some(x), Some(y))
  }

  //The math behind ECC is too complicated to fully explain in comments
  //See https://github.com/jimmysong/programmingbitcoin/blob/master/ch03.asciidoc
  pub fn verify_signature(&self, z: &U256, signature: &Signature) -> bool {
    let z = U512::from(z);
    let r = U512::from(signature.r);
    let s_inverse = U512::from(pow_mod(
      signature.s.clone(),
      N.clone() - U256::from(2),
      N.clone(),
    ));
    let u = z.clone() * s_inverse.clone() % U512::from(N.clone());
    let v = r * s_inverse % U512::from(N.clone());
    let total = G.clone() * U256::from(u) + self * U256::from(v);
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
    let mut x_bytes = vec![0; 32];
    let mut y_bytes = vec![0; 32];
    x.to_big_endian(&mut x_bytes);
    y.to_big_endian(&mut y_bytes);

    if compressed {
      if y.clone() % U256::from(2) == U256::zero() {
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

  pub fn hash_160(&self, compressed: bool) -> Vec<u8> {
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
      (Some(x), Some(y)) => {
        let mut x_bytes = vec![0; 32];
        let mut y_bytes = vec![0; 32];
        x.num.to_big_endian(&mut x_bytes);
        y.num.to_big_endian(&mut x_bytes);
        write!(f, "x={}, y={}", hex::encode(x_bytes), hex::encode(y_bytes))
      }
      (None, Some(y)) => {
        let mut y_bytes = vec![0; 32];
        y.num.to_big_endian(&mut y_bytes);
        panic!(
          "(None, {}) is not on the SECP256K1 curve",
          hex::encode(y_bytes)
        )
      }
      (Some(x), None) => {
        let mut x_bytes = vec![0; 32];
        x.num.to_big_endian(&mut x_bytes);
        panic!(
          "({}, None) is not on the SECP256K1 curve",
          hex::encode(x_bytes)
        )
      }
    }
  }
}

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

impl_op_ex!(*|a: &S256Point, b: &U256| -> S256Point {
  let mut coefficient = b.clone() % N.clone();
  let mut current = a.to_owned();
  let mut result = S256Point::point_at_infinity();
  while &coefficient > &U256::zero() {
    if coefficient.clone() & U256::from(1) == U256::from(1) {
      result = result + &current;
    }
    current = &current + &current;
    coefficient = coefficient >> 1;
  }
  result
});

#[derive(Debug)]
pub struct Signature {
  r: U256,
  s: U256,
}

impl fmt::Display for Signature {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let mut r_bytes = vec![0; 32];
    let mut s_bytes = vec![0; 32];
    self.r.to_big_endian(&mut r_bytes);
    self.s.to_big_endian(&mut s_bytes);
    write!(
      f,
      "num: {}, prime: {}",
      hex::encode(r_bytes),
      hex::encode(s_bytes)
    )
  }
}

impl Signature {
  //Serialize signature in DER format
  pub fn der(&self) -> Vec<u8> {
    let mut rbin = vec![0; 32];
    self.r.to_big_endian(&mut rbin);
    if rbin[0] & 0x80 != 0 {
      let mut rbin_without_prefix = rbin.clone();
      rbin = vec![0];
      rbin.append(&mut rbin_without_prefix);
    }
    let mut result_body = vec![2u8, rbin.len() as u8];
    result_body.append(&mut rbin);

    let mut sbin = vec![0; 32];
    self.s.to_big_endian(&mut sbin);
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

#[derive(Debug, Clone)]
pub struct PrivateKey {
  pub secret: U256,
  pub point: S256Point,
}

impl PrivateKey {
  pub fn new(secret: U256) -> PrivateKey {
    let point = G.clone() * &secret;
    PrivateKey { secret, point }
  }

  pub fn from_bytes(bytes: &[u8]) -> Self {
    let secret = U256::from_big_endian(bytes);
    PrivateKey::new(secret)
  }

  pub fn sign(&self, z: &U256) -> Signature {
    let k = self.deterministic_k(z);

    //To avoid overflow
    let r = U512::from((G.clone() * &k).x.unwrap().num);
    let z = U512::from(z);
    let secret = U512::from(self.secret);
    let n_u512 = U512::from(N.clone());

    let k_inverse = U512::from(pow_mod(k.clone(), N.clone() - U256::from(2), N.clone()));
    let mut s = (z.clone() + (r.clone() * secret % n_u512.clone()) % n_u512.clone()) * k_inverse
      % n_u512.clone();
    if s > n_u512.clone() / U512::from(2) {
      s = n_u512.clone() - s;
    }

    Signature {
      r: U256::from(r),
      s: U256::from(s),
    }
  }

  // Wallet import format serialization
  pub fn wif(&self, compressed: bool, testnet: bool) -> String {
    let mut secret_bytes = vec![0; 32];
    self.secret.to_big_endian(&mut secret_bytes);
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

  //looks vastly nicer in Python
  fn deterministic_k(&self, z: &U256) -> U256 {
    let mut k: [u8; 32] = [0; 32];
    let mut v: [u8; 32] = [1; 32];
    let mut z = z.clone();
    if z > N.clone() {
      z = z - N.clone();
    }
    let mut z_bytes = vec![0; 32];
    z.to_big_endian(&mut z_bytes);
    let mut secret_bytes = vec![0; 32];
    self.secret.to_big_endian(&mut secret_bytes);

    let k_message = construct_long_hmac_message(vec![&v, &[0u8], &secret_bytes, &z_bytes]);
    k = get_hmac_result(&k_message, &k);

    v = get_hmac_result(&v, &k);

    let k_message = construct_long_hmac_message(vec![&v, &[1u8], &secret_bytes, &z_bytes]);
    k = get_hmac_result(&k_message, &k);

    v = get_hmac_result(&v, &k);

    loop {
      v = get_hmac_result(&v, &k);
      let candidate = U256::from_big_endian(&v);
      if candidate >= U256::from(1) && candidate < N.clone() {
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
fn fill_to_32_bytes(vector: Vec<u8>) -> [u8; 32] {
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
    &"2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
    &"2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959",
  );
  assert_eq!(point1 + &point2, point2);

  //silly edge case: point at infinity + point at infinity
  let point1 = S256Point::point_at_infinity();
  let point2 = S256Point::point_at_infinity();
  assert_eq!(point1 + point2, S256Point::point_at_infinity());

  //Case 0.1: other is the point at infinity, return self
  let point1 = S256Point::from_hex(
    &"E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13",
    &"AE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D",
  );
  let point2 = S256Point::point_at_infinity();
  assert_eq!(&point1 + point2, point1);

  //Case 1: self.x == other.x, self.y != other.y
  let point1 = S256Point::from_hex(
    &"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    &"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
  );
  let point2 = S256Point::from_hex(
    &"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    &"b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
  );
  assert_eq!(point1 + point2, S256Point::point_at_infinity());

  //Case 2: self.x ≠ other.x
  let point1 = S256Point::from_hex(
    &"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
    &"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
  );
  let point2 = S256Point::from_hex(
    &"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    &"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
  );
  let point3 = S256Point::from_hex(
    &"2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
    &"D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6",
  );
  assert_eq!(point1 + point2, point3);

  //Case 3: I don't think any cases exist for S256K1

  //Case 4: self == other
  let point1 = G.clone();
  let point2 = G.clone();
  let point3 = S256Point::from_hex(
    &"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
    &"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
  );
  assert_eq!(&point1 + &point2, point3);
}

#[test]
fn test_multiply_point_by_scalar() {
  //Stuipd edge case
  assert_eq!(
    S256Point::point_at_infinity() * U256::from(100),
    S256Point::point_at_infinity()
  );

  let generator_point = G.clone();

  //G * 2
  let result = S256Point::from_hex(
    &"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
    &"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
  );
  assert_eq!(&generator_point * U256::from(2), result);

  //G * 1485
  let result = S256Point::from_hex(
    &"c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda",
    &"7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55",
  );

  //G * 2^128
  assert_eq!(&generator_point * U256::from(1485), result);

  let result = S256Point::from_hex(
    &"8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
    &"662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82",
  );
  assert_eq!(
    &generator_point * U256::from(2).pow(U256::from(128)),
    result
  );

  //G * (2^240 + 2^31)
  let result = S256Point::from_hex(
    &"9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116",
    &"10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053",
  );
  assert_eq!(
    generator_point * (U256::from(2).pow(U256::from(240)) + U256::from(2).pow(U256::from(31))),
    result
  );
}

#[test]
fn test_deterministic_k() {
  let my_privkey = PrivateKey::new(U256::one());
  let mut sha256 = Sha256::new();
  sha256.input(b"1");
  let z: [u8; 32] = sha256.result().into();
  let z: U256 = U256::from_big_endian(&z);
  let k = my_privkey.deterministic_k(&z);

  let expected_result =
    U256_from_hex_str(&"f24af0377e1b27fbebae63b3bec9b249b5bb0b0ba975896dbf35d79b189d19d3");
  assert_eq!(k, expected_result);
}

#[test]
fn test_verify_signature() {
  let point = S256Point::from_hex(
    &"887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c",
    &"61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
  );
  let z = U256_from_hex_str(&"ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60");
  let r = U256_from_hex_str(&"ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395");
  let s = U256_from_hex_str(&"068342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4");
  assert!(point.verify_signature(&z, &Signature { r, s }) == true)
}

#[test]
fn test_sign() {
  let private_key = PrivateKey::new(U256::from(1234567890));
  let z = U256::from(987654321);
  let signature = private_key.sign(&z);
  assert!(private_key.point.verify_signature(&z, &signature));
}

#[test]
fn test_serialize_sec() {
  let coefficient = U256::from(pow(999, 3));
  let uncompressed = "049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9";
  let compressed = "039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5";
  let point = G.clone() * coefficient;
  assert_eq!(hex::decode(uncompressed).unwrap(), point.sec(false));
  assert_eq!(hex::decode(compressed).unwrap(), point.sec(true));

  let coefficient = U256::from(123);
  let uncompressed = "04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b";
  let compressed = "03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5";
  let point = G.clone() * coefficient;
  assert_eq!(hex::decode(uncompressed).unwrap(), point.sec(false));
  assert_eq!(hex::decode(compressed).unwrap(), point.sec(true));

  let coefficient = U256::from(42424242);
  let uncompressed = "04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3";
  let compressed = "03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e";
  let point = G.clone() * coefficient;
  assert_eq!(hex::decode(uncompressed).unwrap(), point.sec(false));
  assert_eq!(hex::decode(compressed).unwrap(), point.sec(true));
}

#[test]
fn test_serialize_der() {
  let private_key = PrivateKey::new(U256::from(1234567890));
  let z = U256::from(987654321);
  let signature = private_key.sign(&z);
  let expected_result = "3045022100b5fb2e0b3a79dacbb56b08d7b13c9417c635dd6083201b19f6caba2694583741022043e6313219e0154f23373681d9c39239669163f0bbab5ca7198a9bbc9e33ade2";
  assert_eq!(expected_result, hex::encode(signature.der()));

  let private_key = PrivateKey::new(U256::from(99999));
  let z = U256::from(77777);
  let signature = private_key.sign(&z);
  let expected_result = "304402201c65f69096aba3df70b37b5778d7f6e6376672f859e13ddcd3ddb17f0aa8c84802202294cd6189ac8451137f811e2c0fa2a3fe6a737d472c21d94a4ea9558c9b5be7";
  assert_eq!(expected_result, hex::encode(signature.der()));

  let private_key = PrivateKey::new(U256::from(19891));
  let z = U256::from(13868);
  let signature = private_key.sign(&z);
  let expected_result = "3045022100998c323c9453c385e73c569a1770e35a4e05241acbe8123146e70c1e6896968702202c8ec157da679532be68f95453a2dac37902e6f52f7cc073c6bc19e8789d235b";
  assert_eq!(expected_result, hex::encode(signature.der()));
}

#[test]
fn test_address() {
  //let secret = U256::from(pow(U256::from(888), 3));
  let secret = U256::from(888).pow(U256::from(3));
  let mainnet_address = String::from("148dY81A9BmdpMhvYEVznrM45kWN32vSCN");
  let testnet_address = String::from("mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP");
  let point = G.clone() * secret;
  assert_eq!(point.address(true, false), mainnet_address);
  assert_eq!(point.address(true, true), testnet_address);

  let secret = U256::from(321);
  let mainnet_address = String::from("1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj");
  let testnet_address = String::from("mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP");
  let point = G.clone() * secret;
  assert_eq!(point.address(false, false), mainnet_address);
  assert_eq!(point.address(false, true), testnet_address);

  let secret = U256::from(4242424242u64);
  let mainnet_address = String::from("1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb");
  let testnet_address = String::from("mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s");
  let point = G.clone() * secret;
  assert_eq!(point.address(false, false), mainnet_address);
  assert_eq!(point.address(false, true), testnet_address)
}

#[test]
fn test_wif() {
  let pk = PrivateKey::new(U256_from_hex_str(
    &"0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d",
  ));
  let expected = "5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty";
  assert_eq!(pk.wif(false, false), expected);

  let pk = PrivateKey::new(U256_from_hex_str(
    &"1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f",
  ));
  let expected = "cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg";
  assert_eq!(pk.wif(true, true), expected);
}
