extern crate hex;

extern crate bitcoin;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::address::Address;
use bitcoin::util::key::PrivateKey;
use bitcoin::util::psbt::serialize::Serialize;

use std::str::FromStr;

pub fn sign_bitcoin_transaction() {
  let my_private_key =
    PrivateKey::from_wif("cRh9AiVR2TMDMy8bsybec32hjzRuqsC7vaXahUu5rPXT7zAJBJMU").unwrap();
  let my_public_key = my_private_key.public_key(&Secp256k1::new());
  let my_receiving_address = Address::from_str("mrDeXVBssWwF2v3fv7BF78fGmzDQnFyDxU").unwrap();

  //This is a Bitcoin testnet faucet return address
  let destination_address = Address::from_str("mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB").unwrap();

  let mut raw_tx = Transaction {
    version: 1,
    lock_time: 0,
    input: vec![TxIn {
      previous_output: OutPoint::from_str(
        "0419f50983ac2771f5803a7964f1cbbb7bf67d1ad508e77aee8a544e60b50cff:0",
      )
      .unwrap(),
      script_sig: Script::new(),
      sequence: 0xffffff,
      witness: vec![],
    }],
    output: vec![TxOut {
      value: 3100000, //The TxIn I reference has 3138875 sats, so I'm paying 38875 to miners
      script_pubkey: destination_address.script_pubkey(),
    }],
  };

  let sig_hash = raw_tx.signature_hash(0, &my_receiving_address.script_pubkey(), 1);
  let message = Message::from_slice(&sig_hash).unwrap();
  let mut signature = Secp256k1::new()
    .sign(&message, &my_private_key.key)
    .serialize_der();
  signature.push(1); // sighash type = SIGHASH_ALL
                     //Can't do this in rust_bitcoin 0.2--see comment below

  let script_sig = Builder::new()
    .push_slice(&signature)
    .push_key(&my_public_key)
    .into_script();

  raw_tx.input[0].script_sig = script_sig;
  println!("serialized transaction: {:?}", raw_tx.serialize());
  println!(
    "hexadecimal transaction: {:?}",
    hex::encode(raw_tx.serialize())
  );
  println!("txHash: {:?}", raw_tx.txid());
}

//The transaction in which I received the utxo's that I spend in this code:
//https://live.blockcypher.com/btc-testnet/tx/0419f50983ac2771f5803a7964f1cbbb7bf67d1ad508e77aee8a544e60b50cff/

//The actual transaction described in this code:
//https://live.blockcypher.com/btc-testnet/tx/f259e6e411642ceef41f4b2054e054f9c986afce96cddffd4bd8745ea3fcb760/

//Note re: signature.push(1) on line 45
//This operation does not work in rust-bitcoin 0.2
//rust-bitcoin 0.2 re-exports a newer version of Secp256k1
//in which serializer_der() returns a "secp256k1::SerializedSignature" instead of a vector
//I'm not sure how to append a 1 to a SerializedSignature
//and it didn't seem worth trying too hard to figure out
