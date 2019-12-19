use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};


pub fn read_varint(cursor: &mut Cursor<Vec<u8>>) -> u64 {
  let mut buffer = [0; 1];
  cursor.read(&mut buffer).unwrap();
  match buffer[0] {
    0xfd => cursor.read_u16::<LittleEndian>().unwrap() as u64,
    0xfe => cursor.read_u32::<LittleEndian>().unwrap() as u64,
    0xff => cursor.read_u64::<LittleEndian>().unwrap(),
    _ => buffer[0].into(),
  }
}

pub fn encode_varint(i: u64) -> Vec<u8> {
  if i < 0xfd {
    vec![i as u8]
  } else if i < 0x10000 {
    let mut buf = vec![0; 2];
    LittleEndian::write_u16(&mut buf, i as u16);
    //just concatenating here lol rust
    vec![0xfd].into_iter().chain(buf.into_iter()).collect()
  } else if i < 0x100000000 {
    let mut buf = vec![0; 4];
    LittleEndian::write_u32(&mut buf, i as u32);
    vec![0xfe].into_iter().chain(buf.into_iter()).collect()
  } else {
    let mut buf = vec![0; 8];
    LittleEndian::write_u64(&mut buf, i);
    vec![0xff].into_iter().chain(buf.into_iter()).collect()
  }
}

#[test]
pub fn test_varint() {
  assert_eq!(encode_varint(256u64), vec![0xfd, 0, 1]);

  assert_eq!(encode_varint(0x100ffu64), vec![0xfe, 0xff, 0, 1, 0]);

  assert_eq!(
    encode_varint(0xffffffffffffffffu64),
    vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
  );

  assert_eq!(
    encode_varint(18005558675309),
    vec![0xff, 0x6d, 0xc7, 0xed, 0x3e, 0x60, 0x10, 0, 0]
  );

  assert_eq!(read_varint(&mut Cursor::new(encode_varint(100))), 100);
  assert_eq!(read_varint(&mut Cursor::new(encode_varint(1000))), 1000);
  assert_eq!(read_varint(&mut Cursor::new(encode_varint(100000))), 100000);
  assert_eq!(
    read_varint(&mut Cursor::new(encode_varint(1000000000000000))),
    1000000000000000
  );

  let bigger_than_a_varint = vec![
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x33, 0x33, 0x33, 0x33,
  ];
  let biggest_varint = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

  assert_eq!(
    read_varint(&mut Cursor::new(biggest_varint)),
    read_varint(&mut Cursor::new(bigger_than_a_varint))
  );
}
