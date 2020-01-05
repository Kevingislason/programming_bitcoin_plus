//Adapted from Jimmy Song's Bitcoin library:
//https://github.com/jimmysong/programmingbitcoin/blob/master/code-ch04/ecc.py
extern crate hex;
use crate::helpers::{encode_varint, read_varint};
use crate::cursor::Cursor;
use core::fmt;
use genio::Read;
use core::convert::TryFrom;

#[derive(PartialEq, Debug, Clone)]
pub struct Script {
  elements: Vec<ScriptElement>,
}

impl Script {
  pub fn new(elements: Option<Vec<ScriptElement>>) -> Script {
    match elements {
      None => Script { elements: vec![] },
      Some(elements) => Script { elements },
    }
  }

  //This is a script pubkey--crreates an encumbrance
  pub fn p2pkh(h160: Vec<u8>) -> Script {
    let elements = vec![
      ScriptElement::Opcode(Opcode::OpDup),
      ScriptElement::Opcode(Opcode::OpHash160),
      ScriptElement::Data(h160),
      ScriptElement::Opcode(Opcode::OpEqualVerify),
      ScriptElement::Opcode(Opcode::OpCheckSig),
    ];
    Script { elements }
  }

  pub const MAX_SCRIPT_ELEMENT_LENGTH: u16 = 520;

  pub fn parse(cursor: &mut Cursor<Vec<u8>>) -> Script {
    let length = read_varint(cursor);
    let mut elements: Vec<ScriptElement> = vec![];
    let mut bytes_parsed = 0;
    while bytes_parsed < length {
      let mut buffer = [0u8; 1];
      cursor.read_exact(&mut buffer).unwrap();
      bytes_parsed += 1;
      let current_byte = buffer[0];

      //Case 1: We are going to parse an element of up to 75 bytes
      if current_byte >= 1 && current_byte <= 75 {
        //We read n bytes, where n=current_byte
        let data_length = current_byte;
        //Read that many bytes as a single element, and add it to our list of commands
        let mut buffer = vec![0u8; data_length as usize];

        cursor
          .read_exact(&mut buffer)
          .unwrap();
        elements.push(ScriptElement::Data(buffer));
        bytes_parsed += data_length as u64;
      }
      //Case 2: We are going to parse an element of 75-255 bytes
      else if current_byte == Opcode::OpPushData1.value() {
        //Find out exactly how many bytes to read
        let mut buffer = [0u8; 1];
        cursor.read_exact(&mut buffer).unwrap();
        let data_length = buffer[0];
        //Read that many bytes as a single element, and add it to our list of commands
        let mut buffer = vec![0u8; data_length as usize];
        cursor
          .read_exact(&mut buffer)
          .unwrap();
        elements.push(ScriptElement::Data(buffer));
        bytes_parsed += 1 + data_length as u64;
      }
      //Case 3: We are going to parse an element of 256-520 bytes
      else if current_byte == Opcode::OpPushData2.value() {
        //Find out exactly how many bytes to read
        let data_length = cursor.read_u16_little_endian().unwrap();
        if data_length > Script::MAX_SCRIPT_ELEMENT_LENGTH {
          panic!("Parse script failed; script elements can be no longer than 520 bytes");
        }
        //Read that many bytes as a single element, and add it to our list of elements
        let mut buffer = vec![0u8; data_length as usize];
        cursor
          .read_exact(&mut buffer)
          .unwrap();
        elements.push(ScriptElement::Data(buffer));
        bytes_parsed += 2 + data_length as u64;
      }
      //Case 4: We are going to parse an Opcode
      else {
        let opcode = Opcode::try_from(current_byte).unwrap();
        elements.push(ScriptElement::Opcode(opcode));
      }
    }
    if bytes_parsed < length {
      panic!("Parse script failed: specified length is incorrect");
    }
    Script { elements }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut raw_serialization = vec![];
    for element in &self.elements {
      match element {
        //If we're dealing with an opcode, we just get its value and throw it in
        ScriptElement::Opcode(opcode) => raw_serialization.push(opcode.value()),
        //If we're dealing with data...
        ScriptElement::Data(data) => {
          //We prepend its length if it is quite short
          if data.len() < 75 {
            raw_serialization.push(data.len() as u8);
          //Otherwise we prepend OpPushData 1 or 2 i.e. 76 or 77
          } else if data.len() < 100 {
            raw_serialization.push(Opcode::OpPushData1.value());
          } else if data.len() <= 520 {
            raw_serialization.push(Opcode::OpPushData2.value());
          }
          raw_serialization.append(&mut data.clone());
        }
      };
    }
    //Prepend a varint equal to the raw serialization's length
    let serialized_script_length = raw_serialization.len() as u64;
    let varint = encode_varint(serialized_script_length);
    let mut serialized_script = varint;
    serialized_script.append(&mut raw_serialization);
    serialized_script
  }
}

impl fmt::Display for Script {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Elements: {:?}", &self.elements)
  }
}

#[derive(PartialEq, Debug, Clone)]
pub enum ScriptElement {
  Opcode(Opcode),
  Data(Vec<u8>), //Hashes and sigs and cool stuff like that
}

impl ScriptElement {
  pub fn data_value(&self) -> Vec<u8> {
    match self {
      ScriptElement::Data(data) => data.clone(),
      ScriptElement::Opcode(_) => panic!("Cannot get data value of an opcode, which is not data"),
    }
  }
}

#[derive(PartialEq, Debug, Clone)]
pub enum Opcode {
  Op0,
  OpPushData1,
  OpPushData2,
  OpPushData4,
  Op1Negate,
  Op1,
  Op2,
  Op3,
  Op4,
  Op5,
  Op6,
  Op7,
  Op8,
  Op9,
  Op10,
  Op11,
  Op12,
  Op13,
  Op14,
  Op15,
  Op16,
  OpNop,
  OpIf,
  OpNotIf,
  OpElse,
  OpEndIf,
  OpVerify,
  OpReturn,
  OpToaltStack,
  OpFromAltStack,
  Op2Drop,
  Op2Dup,
  Op3Dup,
  Op2Over,
  Op2Rot,
  Op2Swap,
  OpIfDup,
  OpDepth,
  OpDrop,
  OpDup,
  OpNip,
  OpOver,
  OpPick,
  OpRoll,
  OpRot,
  OpSwap,
  OpTuck,
  OpSize,
  OpEqual,
  OpEqualVerify,
  Op1Add,
  Op1Sub,
  OpNegate,
  OpAbs,
  OpNot,
  Op0NotEqual,
  OpAdd,
  OpSub,
  OpMul,
  OpBoolAnd,
  OpBoolOr,
  OpNumEqual,
  OpNumEqualVerify,
  OpNumNotEqual,
  OpLessThan,
  OpGreaterThan,
  OpLessThanOrEqual,
  OpGreaterThanOrEqual,
  OpMin,
  OpMax,
  OpWithin,
  OpRipemd160,
  OpSha1,
  OpSha256,
  OpHash160,
  OpHash256,
  OpCodeSeparator,
  OpCheckSig,
  OpCheckSigVerify,
  OpCheckMultiSig,
  OpCheckMultiSigVerify,
  OpNop1,
  OpCheckLockTimeVerify,
  OpCheckSequenceVerify,
  OpNop4,
  OpNop5,
  OpNop6,
  OpNop7,
  OpNop8,
  OpNop9,
  OpNop10,
}

impl Opcode {
  pub fn value(&self) -> u8 {
    match self {
      Opcode::Op0 => 0,
      Opcode::OpPushData1 => 76,
      Opcode::OpPushData2 => 77,
      Opcode::OpPushData4 => 78,
      Opcode::Op1Negate => 79,
      Opcode::Op1 => 81,
      Opcode::Op2 => 82,
      Opcode::Op3 => 83,
      Opcode::Op4 => 84,
      Opcode::Op5 => 85,
      Opcode::Op6 => 86,
      Opcode::Op7 => 87,
      Opcode::Op8 => 88,
      Opcode::Op9 => 89,
      Opcode::Op10 => 90,
      Opcode::Op11 => 91,
      Opcode::Op12 => 92,
      Opcode::Op13 => 93,
      Opcode::Op14 => 94,
      Opcode::Op15 => 95,
      Opcode::Op16 => 96,
      Opcode::OpNop => 97,
      Opcode::OpIf => 99,
      Opcode::OpNotIf => 100,
      Opcode::OpElse => 103,
      Opcode::OpEndIf => 104,
      Opcode::OpVerify => 105,
      Opcode::OpReturn => 106,
      Opcode::OpToaltStack => 107,
      Opcode::OpFromAltStack => 108,
      Opcode::Op2Drop => 109,
      Opcode::Op2Dup => 110,
      Opcode::Op3Dup => 111,
      Opcode::Op2Over => 112,
      Opcode::Op2Rot => 113,
      Opcode::Op2Swap => 114,
      Opcode::OpIfDup => 115,
      Opcode::OpDepth => 116,
      Opcode::OpDrop => 117,
      Opcode::OpDup => 118,
      Opcode::OpNip => 119,
      Opcode::OpOver => 120,
      Opcode::OpPick => 121,
      Opcode::OpRoll => 122,
      Opcode::OpRot => 123,
      Opcode::OpSwap => 124,
      Opcode::OpTuck => 125,
      Opcode::OpSize => 130,
      Opcode::OpEqual => 135,
      Opcode::OpEqualVerify => 136,
      Opcode::Op1Add => 139,
      Opcode::Op1Sub => 140,
      Opcode::OpNegate => 143,
      Opcode::OpAbs => 144,
      Opcode::OpNot => 145,
      Opcode::Op0NotEqual => 146,
      Opcode::OpAdd => 147,
      Opcode::OpSub => 148,
      Opcode::OpMul => 149,
      Opcode::OpBoolAnd => 154,
      Opcode::OpBoolOr => 155,
      Opcode::OpNumEqual => 156,
      Opcode::OpNumEqualVerify => 157,
      Opcode::OpNumNotEqual => 158,
      Opcode::OpLessThan => 159,
      Opcode::OpGreaterThan => 160,
      Opcode::OpLessThanOrEqual => 161,
      Opcode::OpGreaterThanOrEqual => 162,
      Opcode::OpMin => 163,
      Opcode::OpMax => 164,
      Opcode::OpWithin => 165,
      Opcode::OpRipemd160 => 166,
      Opcode::OpSha1 => 167,
      Opcode::OpSha256 => 168,
      Opcode::OpHash160 => 169,
      Opcode::OpHash256 => 170,
      Opcode::OpCodeSeparator => 171,
      Opcode::OpCheckSig => 172,
      Opcode::OpCheckSigVerify => 173,
      Opcode::OpCheckMultiSig => 174,
      Opcode::OpCheckMultiSigVerify => 175,
      Opcode::OpNop1 => 176,
      Opcode::OpCheckLockTimeVerify => 177,
      Opcode::OpCheckSequenceVerify => 178,
      Opcode::OpNop4 => 179,
      Opcode::OpNop5 => 180,
      Opcode::OpNop6 => 181,
      Opcode::OpNop7 => 182,
      Opcode::OpNop8 => 183,
      Opcode::OpNop9 => 184,
      Opcode::OpNop10 => 185,
    }
  }
}

impl TryFrom<u8> for Opcode {
  type Error = &'static str;

  fn try_from(num: u8) -> Result<Self, Self::Error> {
    let opcode = match num {
      0 => Opcode::Op0,
      76 => Opcode::OpPushData1,
      77 => Opcode::OpPushData2,
      78 => Opcode::OpPushData4,
      79 => Opcode::Op1Negate,
      81 => Opcode::Op1,
      82 => Opcode::Op2,
      83 => Opcode::Op3,
      84 => Opcode::Op4,
      85 => Opcode::Op5,
      86 => Opcode::Op6,
      87 => Opcode::Op7,
      88 => Opcode::Op8,
      89 => Opcode::Op9,
      90 => Opcode::Op10,
      91 => Opcode::Op11,
      92 => Opcode::Op12,
      93 => Opcode::Op13,
      94 => Opcode::Op14,
      95 => Opcode::Op15,
      96 => Opcode::Op16,
      97 => Opcode::OpNop,
      99 => Opcode::OpIf,
      100 => Opcode::OpNotIf,
      103 => Opcode::OpElse,
      104 => Opcode::OpEndIf,
      105 => Opcode::OpVerify,
      106 => Opcode::OpReturn,
      107 => Opcode::OpToaltStack,
      108 => Opcode::OpFromAltStack,
      109 => Opcode::Op2Drop,
      110 => Opcode::Op2Dup,
      111 => Opcode::Op3Dup,
      112 => Opcode::Op2Over,
      113 => Opcode::Op2Rot,
      114 => Opcode::Op2Swap,
      115 => Opcode::OpIfDup,
      116 => Opcode::OpDepth,
      117 => Opcode::OpDrop,
      118 => Opcode::OpDup,
      119 => Opcode::OpNip,
      120 => Opcode::OpOver,
      121 => Opcode::OpPick,
      122 => Opcode::OpRoll,
      123 => Opcode::OpRot,
      124 => Opcode::OpSwap,
      125 => Opcode::OpTuck,
      130 => Opcode::OpSize,
      135 => Opcode::OpEqual,
      136 => Opcode::OpEqualVerify,
      139 => Opcode::Op1Add,
      140 => Opcode::Op1Sub,
      143 => Opcode::OpNegate,
      144 => Opcode::OpAbs,
      145 => Opcode::OpNot,
      146 => Opcode::Op0NotEqual,
      147 => Opcode::OpAdd,
      148 => Opcode::OpSub,
      149 => Opcode::OpMul,
      154 => Opcode::OpBoolAnd,
      155 => Opcode::OpBoolOr,
      156 => Opcode::OpNumEqual,
      157 => Opcode::OpNumEqualVerify,
      158 => Opcode::OpNumNotEqual,
      159 => Opcode::OpLessThan,
      160 => Opcode::OpGreaterThan,
      161 => Opcode::OpLessThanOrEqual,
      162 => Opcode::OpGreaterThanOrEqual,
      163 => Opcode::OpMin,
      164 => Opcode::OpMax,
      165 => Opcode::OpWithin,
      166 => Opcode::OpRipemd160,
      167 => Opcode::OpSha1,
      168 => Opcode::OpSha256,
      169 => Opcode::OpHash160,
      170 => Opcode::OpHash256,
      171 => Opcode::OpCodeSeparator,
      172 => Opcode::OpCheckSig,
      173 => Opcode::OpCheckSigVerify,
      174 => Opcode::OpCheckMultiSig,
      175 => Opcode::OpCheckMultiSigVerify,
      176 => Opcode::OpNop1,
      177 => Opcode::OpCheckLockTimeVerify,
      178 => Opcode::OpCheckSequenceVerify,
      179 => Opcode::OpNop4,
      180 => Opcode::OpNop5,
      181 => Opcode::OpNop6,
      182 => Opcode::OpNop7,
      183 => Opcode::OpNop8,
      184 => Opcode::OpNop9,
      185 => Opcode::OpNop10,
      _ => return Err("The given number does not correspond to an opcode"),
    };
    Ok(opcode)
  }
}

//todo: test more exhaustively
#[test]
fn test_parse_script() {
  let serialized_script = hex::decode("6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937").unwrap();
  let script = Script::parse(&mut Cursor::new(serialized_script));

  let want = hex::decode("304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601")
  .unwrap();
  assert_eq!(script.elements[0].data_value(), want);

  let want =
    hex::decode("035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937").unwrap();
  assert_eq!(script.elements[1].data_value(), want);
}

#[test]
fn test_serialize_script() {
  let serialized_script = hex::decode("6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937").unwrap();
  let script = Script::parse(&mut Cursor::new(serialized_script.clone()));
  let my_serialized_script = script.serialize();
  assert_eq!(my_serialized_script, serialized_script);
}
