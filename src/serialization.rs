use genio::Write;
use void::Void;

//Just a simple wrapper around a Vec<u8>
//Doesn't use std::io::write, which doesn't work on embedded devices
#[derive(Debug)]
pub struct Serialization {
  pub contents: Vec<u8>
}

impl Serialization {
  pub fn new() -> Serialization {
    Serialization { contents: vec![]}
  }

  //This functionality really belongs in genio's Write trait
  //but I'm having problems with genio's byteorder feature
  pub fn write_u16_little_endian(&mut self, number: u16) -> Result<usize, <Serialization as Write>::WriteError> {
    let buf = number.to_le_bytes();
    return self::Write::write(self, &buf)
  }

  pub fn write_u32_little_endian(&mut self, number: u32) -> Result<usize, <Serialization as Write>::WriteError> {
    let buf = number.to_le_bytes();
    return self::Write::write(self, &buf)
  }

  pub fn write_u64_little_endian(&mut self, number: u64) -> Result<usize, <Serialization as Write>::WriteError> {
    let buf = number.to_le_bytes();
    return self::Write::write(self, &buf)
  }

}

impl Write for Serialization {
  type WriteError = Void;
  type FlushError = Void;

  fn write(&mut self, buf: &[u8]) -> Result<usize, Self::WriteError> {
      self.contents.extend_from_slice(buf);
      Ok(buf.len())
  }

  fn flush(&mut self) -> Result<(), Self::FlushError> {
      Ok(())
  }

  fn size_hint(&mut self, bytes: usize) {
      self.contents.reserve(bytes)
  }
}


//todo: write tests
// #[test]
// pub fn test_serialization() {
//   unimplemented!();
// }
