#![allow(dead_code)]
#![feature(const_int_pow)]

mod cursor;
mod ecc;
mod hd_wallet;
mod helpers;
mod script;
mod seed_phrase;
mod serialization;
mod tx;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate auto_ops;

#[macro_use]
extern crate alloc;
extern crate genio;
extern crate hmac;
extern crate sha2;
extern crate void;

use bigint::U256;
use ecc::PrivateKey;
use helpers::decode_base58;
use script::Script;
use tx::{Tx, TxIn, TxOut};

// Example transaction
fn main() {
    let my_secret = U256::from_dec_str(
        &"22479429793217560129393058838969219348384516947386592241923862165759284190250",
    )
    .unwrap();
    let my_private_key = PrivateKey::new(my_secret);

    //Define tx in
    let prev_tx_id = U256::from_big_endian(
        &hex::decode("f26d43ce30409a3c99cad136b5bc3535eca062ec6c901b3b81a488a18e523d9b").unwrap(),
    );
    let prev_index = 1u32;
    let script_sig = Script::new(None);
    let sequence = 0xffffffff;

    let my_tx_in = TxIn::new(prev_tx_id, prev_index, script_sig, sequence);

    //Define tx out
    let amount = 3077323;
    let target_address = String::from("mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB");
    let target_h160 = decode_base58(target_address);
    println!("target_h160: {:?}", target_h160);
    let script_pubkey = Script::p2pkh(target_h160);

    let my_tx_out = TxOut::new(amount, script_pubkey);

    //Define unsigned tx
    let mut my_tx = Tx::new(1, vec![my_tx_in], vec![my_tx_out], 0, true);

    //Sign tx
    let my_address = my_private_key.point.address(true, true);
    let my_h160 = decode_base58(my_address);
    let my_script_pubkey = Script::p2pkh(my_h160);

    my_tx.sign_input(0, my_private_key, my_script_pubkey);

    println!("{:?}", hex::encode(my_tx.serialize()));

    assert_eq!(
        my_tx.serialize(),
        vec![
            1, 0, 0, 0, 1, 155, 61, 82, 142, 161, 136, 164, 129, 59, 27, 144, 108, 236, 98, 160,
            236, 53, 53, 188, 181, 54, 209, 202, 153, 60, 154, 64, 48, 206, 67, 109, 242, 1, 0, 0,
            0, 106, 71, 48, 68, 2, 32, 115, 122, 130, 31, 124, 199, 152, 236, 169, 45, 217, 239,
            46, 168, 197, 247, 244, 60, 143, 240, 194, 197, 233, 193, 230, 45, 230, 7, 108, 111,
            84, 82, 2, 32, 53, 67, 229, 129, 125, 92, 69, 14, 39, 97, 135, 106, 76, 149, 1, 66,
            251, 40, 16, 195, 37, 200, 121, 159, 55, 13, 120, 119, 193, 236, 30, 91, 1, 33, 2, 4,
            19, 54, 42, 181, 25, 213, 189, 3, 234, 113, 26, 230, 66, 92, 10, 58, 63, 244, 188, 64,
            172, 38, 180, 3, 99, 170, 104, 41, 223, 69, 132, 255, 255, 255, 255, 1, 203, 244, 46,
            0, 0, 0, 0, 0, 25, 118, 169, 20, 159, 154, 122, 189, 96, 12, 12, 170, 3, 152, 58, 119,
            200, 195, 223, 142, 6, 44, 178, 250, 136, 172, 0, 0, 0, 0
        ]
    );
}

//My receiving address: n1E7zEXhJxLg9r8JvKKA5GMWqJri2EwMQp
//My secret: 22479429793217560129393058838969219348384516947386592241923862165759284190250

//Testnet receiving address: mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB
//Transaction in which I get my initial bitcoin: https://live.blockcypher.com/btc-testnet/tx/f26d43ce30409a3c99cad136b5bc3535eca062ec6c901b3b81a488a18e523d9b/
//amount: 3077323

//Testnet return address: mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB

//correct tx: [1, 0, 0, 0, 1, 155, 61, 82, 142, 161, 136, 164, 129, 59, 27, 144, 108, 236, 98, 160, 236, 53, 53, 188, 181, 54, 209, 202, 153, 60, 154, 64, 48, 206, 67, 109, 242, 1, 0, 0, 0, 25, 118, 169, 20, 216, 51, 137, 18, 41, 216, 173, 112, 75, 229, 225, 28, 146, 0, 11, 65, 46, 113, 209, 62, 136, 172, 255, 255, 255, 255, 1, 192, 198, 45, 0, 0, 0, 0, 0, 25, 118, 169, 20, 159, 154, 122, 189, 96, 12, 12, 170, 3, 152, 58, 119, 200, 195, 223, 142, 6, 44, 178, 250, 136, 172, 0, 0, 0, 0, 1, 0, 0, 0]

//https://live.blockcypher.com/btc-testnet/tx/5910b62c572ee9f3f446564eb1b01d4429fba02219f9e04edfaf2870e934d9cf/
