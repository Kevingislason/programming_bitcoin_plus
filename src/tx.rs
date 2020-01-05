//Adapted from Jimmy Song's Programming Bitcoin library:
//https://github.com/jimmysong/programmingbitcoin/
use crate::ecc::PrivateKey;
use crate::script::{Script, ScriptElement};
use crate::helpers::{encode_varint, read_varint, hash_256, SIGHASH_ALL};
use crate::cursor::Cursor;
use crate::genio::{Read, Write};
use crate::serialization::Serialization;

use bigint::uint::U256;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use core::convert::TryFrom;
use core::fmt;
use hex::decode;
use num::bigint::BigInt;
use num::bigint::Sign::Plus;
use num::Zero;



//A Bitcoin transction
#[derive(PartialEq, Debug, Clone)]
pub struct Tx {
  pub version: u32,
  pub tx_ins: Vec<TxIn>,
  pub tx_outs: Vec<TxOut>,
  pub locktime: u32,
  pub testnet: bool,
}

impl Tx {
  pub fn new(
    version: u32,
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    locktime: u32,
    testnet: bool,
  ) -> Tx {
    Tx {
      version,
      tx_ins,
      tx_outs,
      locktime,
      testnet,
    }
  }

  //todo: how can I tell if this is a testnet tx
  pub fn parse(serialization: Vec<u8>, testnet: bool) -> Tx {
    let mut cursor = Cursor::new(serialization);
    let version = cursor.read_u32_little_endian().unwrap();

    let total_tx_ins = read_varint(&mut cursor);
    let mut tx_ins = vec![];
    for _ in 0..total_tx_ins {
      tx_ins.push(TxIn::parse(&mut cursor));
    }

    let total_tx_outs = read_varint(&mut cursor);
    let mut tx_outs = vec![];
    for _ in 0..total_tx_outs {
      tx_outs.push(TxOut::parse(&mut cursor));
    }
    let locktime = cursor.read_u32_little_endian().unwrap();

    return Tx {
      version,
      tx_ins,
      tx_outs,
      locktime,
      testnet,
    };
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialization = Serialization::new();
    serialization
      .write_u32_little_endian(self.version)
      .unwrap();
    serialization
      .write(&encode_varint(self.tx_ins.len() as u64))
      .unwrap();
    for tx_in in &self.tx_ins {
      serialization.write(&tx_in.serialize()).unwrap();
    }
    serialization
      .write(&encode_varint(self.tx_outs.len() as u64))
      .unwrap();
    for tx_out in &self.tx_outs {
      serialization.write(&tx_out.serialize()).unwrap();
    }
    serialization
      .write_u32_little_endian(self.locktime)
      .unwrap();

    serialization.contents
  }

  fn sig_hash(&self, input_index: usize, redeem_script: Script) -> BigInt {
    let mut serialization = Serialization::new();
    serialization
      .write_u32_little_endian(self.version)
      .unwrap();
    serialization
      .write(&encode_varint(self.tx_ins.len() as u64))
      .unwrap();
    let mut script_sig: Script;
    for (i, tx_in) in self.tx_ins.iter().enumerate() {
      if i == input_index {
        script_sig = redeem_script.clone();
      } else {
        script_sig = Script::new(None);
      }
      let altered_tx_in = TxIn::new(
        tx_in.prev_tx_id,
        tx_in.prev_index,
        script_sig,
        tx_in.sequence,
      );
      serialization.write(&altered_tx_in.serialize()).unwrap();
    }
    serialization
      .write(&encode_varint(self.tx_outs.len() as u64))
      .unwrap();

    for tx_out in &self.tx_outs {
      serialization.write(&tx_out.serialize()).unwrap();
    }
    serialization
      .write_u32_little_endian(self.locktime)
      .unwrap();

    serialization
      .write_u32_little_endian(SIGHASH_ALL as u32)
      .unwrap();

    let hash = hash_256(serialization.contents);
    BigInt::from_bytes_be(Plus, &hash)
  }

  pub fn sign_input(&mut self, input_index: usize, private_key: PrivateKey, redeem_script: Script) {
    let z = self.sig_hash(input_index, redeem_script);
    let mut sig = private_key.sign(&z).der();
    sig.push(SIGHASH_ALL);
    let sec = private_key.point.sec(true);
    let script_sig_elements = vec![ScriptElement::Data(sig), ScriptElement::Data(sec)];
    let script_sig = Script::new(Some(script_sig_elements));
    self.tx_ins[input_index].script_sig = script_sig;
  }
}

//I'm sure this will look very ugly, oh well
impl fmt::Display for Tx {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "version: {}, tx_ins: {:?}, tx_outs: {:?}, locktime: {}, testnet: {}",
      &self.version, &self.tx_ins, &self.tx_outs, &self.locktime, &self.testnet
    )
  }
}

#[derive(PartialEq, Debug, Clone)]
pub struct TxIn {
  pub prev_tx_id: U256, //u256
  prev_index: u32,
  script_sig: Script,
  sequence: u32,
}

impl TxIn {
  pub fn new(
    prev_tx_id: U256, //
    prev_index: u32,
    script_sig: Script,
    sequence: u32,
  ) -> TxIn {
    TxIn {
      prev_tx_id,
      prev_index,
      script_sig,
      sequence,
    }
  }

  pub fn parse(cursor: &mut Cursor<Vec<u8>>) -> TxIn {
    let mut buffer = [0u8; 32];
    cursor.read_exact(&mut buffer).unwrap();
    let prev_tx_id = U256::from_little_endian(&buffer);
    println!("Prev tx id: {}", prev_tx_id);
    let prev_index = cursor.read_u32_little_endian().unwrap();
    let script_sig = Script::parse(cursor);
    let sequence = cursor.read_u32_little_endian().unwrap();

    TxIn {
      prev_tx_id,
      prev_index,
      script_sig,
      sequence,
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialization = Serialization::new();
    //serialize prev tx id
    let mut buf = vec![0; 32];
    self.prev_tx_id.to_little_endian(&mut buf);
    serialization.write(&buf).unwrap();
    //serialize prev index
    serialization
      .write_u32_little_endian(self.prev_index)
      .unwrap();
    //serialize script sig
    serialization.write(&self.script_sig.serialize()).unwrap();
    serialization
      .write_u32_little_endian(self.sequence)
      .unwrap();
    serialization.contents
  }
}


impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "prev_tx_id: {}, prev_index: {}, script_sig: {}, sequence: {}",
      &self.prev_tx_id, &self.prev_index, &self.script_sig, &self.sequence
    )
  }
}

#[derive(PartialEq, Debug, Clone)]
pub struct TxOut {
  amount: u64,
  script_pubkey: Script,
}

impl TxOut {
  pub fn new(amount: u64, script_pubkey: Script) -> TxOut {
    TxOut {
      amount,
      script_pubkey,
    }
  }

  pub fn parse(cursor: &mut Cursor<Vec<u8>>) -> TxOut {
    let amount = cursor.read_u64_little_endian().unwrap();
    let script_pubkey = Script::parse(cursor);
    TxOut {
      amount,
      script_pubkey,
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialization = Serialization::new();
    serialization
      .write_u64_little_endian(self.amount)
      .unwrap();
    serialization
      .write(&self.script_pubkey.serialize())
      .unwrap();
    serialization.contents
  }
}

impl fmt::Display for TxOut {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "Amount: {}, Script_pubkey: {}",
      &self.amount, &self.script_pubkey
    )
  }
}

#[test]
pub fn test_parse_version() {
  let serialized_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
  let tx = Tx::parse(serialized_tx, false);
  assert_eq!(tx.version, 1);
}

#[test]
pub fn test_parse_inputs() {
  let serialized_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();

  let tx = Tx::parse(serialized_tx, false);
  assert_eq!(tx.tx_ins.len(), 1);

  let want =
    hex::decode("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81").unwrap();
  let prev_tx_id = tx.tx_ins[0].prev_tx_id;
  let mut prev_tx_id_slice = [0; 32];
  prev_tx_id.to_big_endian(&mut prev_tx_id_slice);
  assert_eq!(prev_tx_id_slice.to_vec(), want);
  assert_eq!(tx.tx_ins[0].prev_index, 0);
  let want = hex::decode("6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a").unwrap();

  assert_eq!(tx.tx_ins[0].script_sig.serialize(), want);
  assert_eq!(tx.tx_ins[0].sequence, 0xfffffffe);
}

#[test]
pub fn test_parse_outputs() {
  let serialized_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
  let tx = Tx::parse(serialized_tx, false);
  assert_eq!(tx.tx_outs.len(), 2);
  let want = 32454049;
  assert_eq!(tx.tx_outs[0].amount, want);
  let want = hex::decode("1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac").unwrap();
  assert_eq!(tx.tx_outs[0].script_pubkey.serialize(), want);
  let want = 10011545;
  assert_eq!(tx.tx_outs[1].amount, want);
  let want = hex::decode("1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac").unwrap();
  assert_eq!(tx.tx_outs[1].script_pubkey.serialize(), want);
}

#[test]
pub fn test_parse_locktime() {
  let serialized_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
  let tx = Tx::parse(serialized_tx, false);
  assert_eq!(tx.locktime, 410393);
}

//todo: implement fees

// #[test]
// pub fn test_fee() {
//   let serialized_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
//   let tx = Tx::parse(serialized_tx);
//   assert_eq!(tx.fee())

// }
