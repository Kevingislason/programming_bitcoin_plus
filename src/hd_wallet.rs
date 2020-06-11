use crate::cursor::Cursor;
use crate::ecc::{PrivateKey, N};
use crate::helpers::{hash_160, hmac_512};
use crate::seed_phrase::SeedPhrase;
use bigint::{U256, U512};
use byteorder::{BigEndian, WriteBytesExt};
use core::convert::TryInto;
use genio::Read;
//use sha2::Digest;
use hashbrown::HashMap;
//use hex::decode;
use hmac::Hmac;

//todo: test
#[derive(Debug, Clone)]
pub struct ChainCode(U256);

impl ChainCode {
  pub fn new(value: U256) -> Self {
    Self(value)
  }

  pub fn from_bytes(bytes: &[u8]) -> Self {
    Self(U256::from_big_endian(bytes))
  }

  pub fn as_bytes(&self) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    self.0.to_big_endian(&mut bytes);
    bytes
  }
}

#[derive(Debug, Clone)]
pub struct ExtendedPrivateKey {
  private_key: PrivateKey,
  chain_code: ChainCode,
  depth: u8,
  parent_fingerprint: u32,
  child_number: u32,
  unhardened_children: HashMap<u32, Self>,
  hardened_children: HashMap<u32, Self>,
}

impl ExtendedPrivateKey {
  //todo: double check
  //#![feature(const_int_pow)]
  const HARDENED_CHILD_KEY_BASE_INDEX: u32 = 2u32.pow(31);

  pub fn new(
    private_key: PrivateKey,
    chain_code: ChainCode,
    parent_fingerprint: u32,
    child_number: u32,
    depth: u8,
  ) -> Self {
    Self {
      private_key,
      chain_code,
      child_number,
      parent_fingerprint,
      unhardened_children: HashMap::new(),
      hardened_children: HashMap::new(),
      depth,
    }
  }

  pub fn new_master(seed: HDSeed) -> Self {
    let hmac_result = hmac_512(b"Bitcoin seed", &seed.as_bytes());
    let private_key_bytes: [u8; 32] = hmac_result[..32].try_into().expect("");
    let private_key = PrivateKey::from_bytes(&private_key_bytes);
    let chain_code_bytes: [u8; 32] = hmac_result[32..].try_into().expect("");
    let chain_code = ChainCode::from_bytes(&chain_code_bytes);
    let mut hardened_children = HashMap::new();
    let mut unhardened_children = HashMap::new();

    Self {
      private_key,
      chain_code,
      child_number: 0,
      parent_fingerprint: 0,
      unhardened_children,
      hardened_children,
      depth: 0,
    }
  }

  // Given a derivation path, populate this key's child, grandchild, etc.
  //Example paths: "h/0h/1/33", "h/0h/"
  pub fn reconstruct_by_path(&mut self, path: HDDerivationPath) -> Result<&Self, &'static str> {
    let mut tokens = path.as_tokens().into_iter();
    let mut current_node = self;
    if tokens.next().unwrap() != "m" {
      return Err("Invalid derivation path; derivation paths must begin with 'm' (master)");
    }

    while let Some(token) = tokens.next() {
      // If token ends in "h", compute hardened child
      if token.chars().last().unwrap() == 'h' {
        match u32::from_str_radix(&token[..token.len() - 1], 10) {
          Ok(child_number) => {
            let child_number = child_number + Self::HARDENED_CHILD_KEY_BASE_INDEX;
            current_node.derive_hardened_child_private_key(child_number);
            current_node = current_node
              .hardened_children
              .get_mut(&child_number)
              .unwrap();
          }
          Err(_) => return Err("Invalid derivation path"),
        }

      // Else compute unhardened child
      } else {
        match u32::from_str_radix(&token, 10) {
          Ok(child_number) => {
            current_node.derive_unhardened_child_private_key(child_number);
            current_node = current_node
              .unhardened_children
              .get_mut(&child_number)
              .unwrap();
          }
          Err(_) => return Err("Invalid derivation path"),
        };
      }
    }
    Ok(current_node)
  }

  pub fn derive_hardened_child_private_key(&mut self, new_child_number: u32) {
    // Hardened keys begin at 2**31
    assert!(new_child_number >= Self::HARDENED_CHILD_KEY_BASE_INDEX);

    // Check if this key has already been derived
    if let Some(extended_private_key) = self.hardened_children.get(&new_child_number) {
      return; //extended_private_key.clone();
    }

    // Follow the formula: HMAC(key=chain_code_bytes, message=(0x00 || privkey || index)
    let mut hmac_message = vec![0x00];

    let mut private_key_bytes = vec![0x00; 32];
    self
      .private_key
      .secret
      .to_big_endian(&mut private_key_bytes);
    hmac_message.extend(private_key_bytes);

    let mut new_child_number_bytes = vec![];
    new_child_number_bytes
      .write_u32::<BigEndian>(new_child_number)
      .unwrap();
    hmac_message.extend(new_child_number_bytes);

    let hmac_result = hmac_512(&self.chain_code.as_bytes(), &hmac_message);

    // Chaincode is the first 32 bytes of the HMAC result;
    let new_child_chaincode = ChainCode::from_bytes(&hmac_result[32..]);

    // privkey is (last 32 bytes of HMAC + the old privkey) % N
    let new_secret = (U256::from_big_endian(&hmac_result[..32])
      .overflowing_add(self.private_key.secret)
      .0)
      % N.clone();
    //(U256::from_big_endian(&hmac_result[..32]) + self.private_key.secret) % N.clone();
    let new_child_private_key = PrivateKey::new(new_secret);

    let new_child_extended_private_key = Self::new(
      new_child_private_key,
      new_child_chaincode,
      self.fingerprint(),
      new_child_number,
      self.depth + 1,
    );

    self
      .hardened_children
      .insert(new_child_number, new_child_extended_private_key);

    //new_child_extended_private_key
  }

  pub fn derive_unhardened_child_private_key(&mut self, new_child_number: u32) {
    // Unhardened keys use all indicies up to 2**31
    assert!(new_child_number < Self::HARDENED_CHILD_KEY_BASE_INDEX);

    // Check if this key has already been derived
    if let Some(extended_private_key) = self.unhardened_children.get(&new_child_number) {
      return;
    }

    // Follow the recipie: HMAC(key=chain_code_bytes, message=(pubkey || index)
    let mut hmac_message = vec![];

    let public_key_bytes = self.private_key.point.sec(true);
    hmac_message.extend(public_key_bytes);

    let mut new_child_number_bytes = vec![];
    new_child_number_bytes
      .write_u32::<BigEndian>(new_child_number)
      .unwrap();
    hmac_message.extend(new_child_number_bytes);

    let hmac_result = hmac_512(&self.chain_code.as_bytes(), &hmac_message);

    // Code gore to prevent overflow; todo: fix
    let new_secret: U512 = (U512::from(self.private_key.secret) + U512::from(&hmac_result[..32]))
      % U512::from(N.clone());
    let new_secret: U256 = U256::from(new_secret);

    let new_child_private_key = PrivateKey::new(new_secret);

    let new_child_chaincode = ChainCode::from_bytes(&hmac_result[32..]);
    let new_child_extended_private_key = Self::new(
      new_child_private_key,
      new_child_chaincode,
      self.fingerprint(),
      new_child_number,
      self.depth + 1,
    );

    self
      .unhardened_children
      .insert(new_child_number, new_child_extended_private_key);
  }

  pub fn fingerprint(&self) -> u32 {
    let fingerprint_slice = &self.private_key.point.hash_160(true)[..4];
    //let fingerprint_slice = &self.private_key.point.sec(true)[..4];
    let mut fingerprint_bytes = [0u8; 4];
    fingerprint_bytes.copy_from_slice(&fingerprint_slice);
    u32::from_be_bytes(fingerprint_bytes)
  }

  pub fn deserialize(bytes: &[u8]) -> Self {
    const EXPECTED_SERIALIZATION_LENTH: usize = 78;
    if bytes.len() != EXPECTED_SERIALIZATION_LENTH {
      panic!("Extended private key must serialization must be exactly 78 bytes");
    }

    let mut version_bytes = [0u8; 4];
    let depth: u8;
    let mut fingerprint_bytes = [0u8; 4];
    let child_number: u32;
    let mut chain_code_bytes = [0u8; 32];
    let mut private_key_bytes = [0u8; 33];

    let mut reader = Cursor::new(bytes);
    reader.read_exact(&mut version_bytes);
    depth = reader.read_u8_big_endian().unwrap();
    reader.read_exact(&mut fingerprint_bytes);
    child_number = reader.read_u32_big_endian().unwrap();
    reader.read_exact(&mut chain_code_bytes);
    reader.read_exact(&mut private_key_bytes);

    let parent_fingerprint = u32::from_be_bytes(fingerprint_bytes);
    let private_key = PrivateKey::from_bytes(&private_key_bytes[1..]);
    let chain_code = ChainCode::from_bytes(&chain_code_bytes);

    Self::new(
      private_key,
      chain_code,
      parent_fingerprint,
      child_number,
      depth,
    )
  }

  pub fn serialize(&self, testnet: bool) -> Vec<u8> {
    let mut serialization = vec![];
    if testnet {
      let version_bytes = vec![0x04, 0x35, 0x83, 0x94];
      serialization.extend(version_bytes);
    } else {
      let version_bytes = vec![0x04, 0x88, 0xAD, 0xE4];
      serialization.extend(version_bytes);
    }
    serialization.extend(vec![self.depth]);

    let parent_fingerprint_bytes = self.parent_fingerprint.to_be_bytes();
    serialization.extend(&parent_fingerprint_bytes);

    let child_number_bytes = self.child_number.to_be_bytes();
    serialization.extend(&child_number_bytes);

    let mut chaincode_bytes = [0u8; 32];
    self.chain_code.0.to_big_endian(&mut chaincode_bytes);
    serialization.extend(&chaincode_bytes);

    serialization.extend(vec![0x00]);

    let mut private_key_bytes = vec![0x00; 32];
    self
      .private_key
      .secret
      .to_big_endian(&mut private_key_bytes);

    serialization.extend(private_key_bytes);

    serialization
  }
}

#[derive(Debug, Clone)]
pub struct HDSeed {
  bytes: Vec<u8>,
}

impl HDSeed {
  pub fn new(bytes: Vec<u8>) -> Self {
    Self { bytes }
  }

  pub fn from_seed_phrase(phrase: &SeedPhrase, password: &str) -> Self {
    const PBKDF2_ROUNDS: usize = 2048;
    const PBKDF2_BYTES: usize = 64;

    let salt = format!("mnemonic{}", password);

    let mut bytes = vec![0u8; PBKDF2_BYTES];
    pbkdf2::pbkdf2::<Hmac<sha2::Sha512>>(
      phrase.0.as_bytes(),
      salt.as_bytes(),
      PBKDF2_ROUNDS,
      &mut bytes,
    );

    Self { bytes }
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }
}

#[derive(Debug, Clone)]
pub struct HDDerivationPath(String);

impl HDDerivationPath {
  pub fn new(path: String) -> Self {
    Self(path)
  }

  pub fn as_tokens(&self) -> Vec<String> {
    self.0.split("/").map(String::from).collect::<Vec<String>>()
  }
}

#[test]
fn test_derive_child_private_keys() {
  let bytes = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
  let seed = HDSeed::new(bytes);
  let mut extended_private_key = ExtendedPrivateKey::new_master(seed);

  let expected_bytes = hex::decode("0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35").unwrap();
  let expected = ExtendedPrivateKey::deserialize(&expected_bytes);

  assert_eq!(
    extended_private_key.serialize(false),
    expected.serialize(false)
  );

  let expected_bytes = hex::decode("0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea").unwrap();
  let expected = ExtendedPrivateKey::deserialize(&expected_bytes);

  let path = HDDerivationPath::new(String::from("m/0h"));
  let child_hardened_key = extended_private_key.reconstruct_by_path(path).unwrap();

  assert_eq!(
    child_hardened_key.serialize(false),
    expected.serialize(false)
  );

  let expected_bytes = hex::decode("0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368").unwrap();

  let expected = ExtendedPrivateKey::deserialize(&expected_bytes);

  let path = HDDerivationPath::new(String::from("m/0h/1"));
  let child_hardened_key = extended_private_key.reconstruct_by_path(path).unwrap();

  assert_eq!(
    child_hardened_key.serialize(false),
    expected.serialize(false)
  )
}
