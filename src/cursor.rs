use genio::{Read};
use genio::bufio::{BufRead};
use genio::error::ReadExactError;
use core::cmp;
use core::result::Result;
use void::Void;


//A no_std compatible cursor
//Implements genio::Read instead of std::io::Read
//Does everything I need it to do and nothing else
#[derive(Debug)]
pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T> Cursor<T> where T: AsRef<[u8]>{
    pub fn new(inner: T) -> Cursor<T> {
        Cursor { pos: 0, inner: inner}
    }

    //This functionality really belongs in genio's Read trait
    //but I'm having problems with genio's byteorder feature not compiling
    pub fn read_u64_little_endian(&mut self) -> Result<u64, ReadExactError<Void>> {
      let mut buf = [0; 8];
      let result = self::Read::read(self, &mut buf).unwrap();
      if result != 8 {
      return Err(ReadExactError::UnexpectedEnd::<Void>)
      }
      Ok(u64::from_le_bytes(buf))
    }

    pub fn read_u32_little_endian(&mut self) -> Result<u32, ReadExactError<Void>> {
      let mut buf = [0; 4];
      let result = self::Read::read(self, &mut buf).unwrap();
      if result != 4 {
      return Err(ReadExactError::UnexpectedEnd::<Void>)
      }
      Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u16_little_endian(&mut self) -> Result<u16, ReadExactError<Void>> {
      let mut buf = [0; 2];
      let result = self::Read::read(self, &mut buf).unwrap();
      if result != 2 {
      return Err(ReadExactError::UnexpectedEnd::<Void>)
      }
      Ok(u16::from_le_bytes(buf))
    }
}

impl<T> BufRead for Cursor<T> where T: AsRef<[u8]> {
    fn fill_buf(&mut self) -> core::result::Result<&[u8], Self::ReadError> {
        let amt = cmp::min(self.pos, self.inner.as_ref().len() as u64);
        Ok(&self.inner.as_ref()[(amt as usize)..])
    }
    fn consume(&mut self, amt: usize) { self.pos += amt as u64; }
}

//todo: use a genio error type; it isn't correct to use Void here, since this can fail
impl<T> Read for Cursor<T> where T: AsRef<[u8]> {
    type ReadError = Void;

    fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, Self::ReadError> {
        let n = genio::Read::read(&mut self.fill_buf()?, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}



//todo:
// #[test]
// pub fn test_cursor() {
//   unimplemented!();
// }
