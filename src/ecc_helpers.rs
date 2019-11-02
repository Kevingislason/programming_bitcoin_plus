use num::bigint::BigInt;
use num::bigint::Sign::Plus;
use num_traits::identities::{One, Zero};
use num::ToPrimitive;

use sha2::{Digest, Sha256};
use ripemd160::Ripemd160;

pub fn hash_160(bytes: Vec<u8>) -> Vec<u8> {
  //Hash our bytes with sha256, then ripemd160
  let mut sha256 = Sha256::new();
  sha256.input(bytes);
  let sha256_result = sha256.result();
  let mut ripemd160 = Ripemd160::new();
  ripemd160.input(sha256_result);
  ripemd160.result().to_vec()
}

pub fn hash_256(bytes: Vec<u8>) -> Vec<u8> {
  let mut sha256 = Sha256::new();
  sha256.input(bytes);
  let sha256_result = sha256.result();
  let mut sha256 = Sha256::new();
  sha256.input(sha256_result);
  sha256.result().to_vec()
}

pub fn encode_base58(bytes: Vec<u8>) -> String {
  let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let mut count = 0;
  for c in bytes.clone() {
    if c == 0 {
      count += 1;
    } else {
      break;
    }
  }
  let mut num = BigInt::from_bytes_be(Plus, &bytes);
  let mut prefix = String::from("");
  for _ in 0..count {
    prefix += "1";
  }
  let mut result = String::from("");
  while &num > &BigInt::zero() {
    let modulo: usize = (&num % 58u8).to_usize().unwrap();
    num = &num / 58;
    let character = String::from(&base58_alphabet[modulo..modulo + 1]);
    result = character + &result;
  }
  return prefix + &result;
}

pub fn encode_base58_checksum(bytes: Vec<u8>) -> String {
  let mut unencoded = bytes.clone();
  let mut last_4_bytes_of_hash = hash_256(bytes)[0..4].to_vec();
  unencoded.append(&mut last_4_bytes_of_hash);
  encode_base58(unencoded)
}

#[test]
pub fn test_enocde_base58() {
  println!("{}", 100u8 / 58u8);
  let bytes: Vec<u8> = vec![1, 2, 200, 255, 122];
  assert_eq!(encode_base58(bytes), "7cfKTo")
}

//todo: write tests for this, I'm almost sure it will not work, but I don't need it yet
pub fn decode_base58(s: String) -> Vec<u8> {
  let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let mut num = BigInt::zero();
  for c in s.chars() {
    num *= 58;
    num = num + &base58_alphabet.find(c).unwrap();
  }
  let mut combined = num.to_bytes_be().1;
  //pad to 25 bytes
  if combined.len() < 25 {
    let padding_len = 25 - combined.len();
    let mut padded_combined: Vec<u8> = vec![0; padding_len];
    padded_combined.append(&mut combined);
    combined = padded_combined;
  }

  let checksum = combined[21..25].to_vec();
  let first_21_chars_of_combined = combined[0..21].to_vec();
  let hash = hash_256(first_21_chars_of_combined);
  if hash[0..4].to_vec() != checksum {
    panic!("bad address: {:?} {:?}", checksum, hash[0..4].to_vec());
  }
  return combined[1..21].to_vec();
}
