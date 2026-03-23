use anyhow::{Result, anyhow};
use std::io::Read;

#[derive(Debug)]
pub struct Wave {
    socket: u32,  // TODO: add socket support
    options: u32, // TODO: add options
    tx: usize,
    rx: usize,
}

impl Wave {
    const WAVE: &[u8] = &[0x77, 0x61, 0x76, 0x65];
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        Ok(0)
    }

    pub fn receive(&mut self) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn package(data: &[u8]) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Self::WAVE.to_vec();
        let length: u32 = data.len().try_into()?;
        out.append(&mut length.to_be_bytes().to_vec());
        out.append(&mut data.to_vec());
        Ok(out)
    }

    fn unpackage(data: &mut impl Read) -> Result<Vec<u8>> {
        let mut check = [0u8; 4];
        data.read_exact(&mut check)?;
        println!("{check:?}");
        if &check != Self::WAVE {
            return Err(anyhow!("Protocol header mismatch!"));
        }

        data.read_exact(&mut check)?;
        println!("{check:?}");
        let length: u32 = u32::from_be_bytes(check);

        let mut buf: Vec<u8> = vec![0; length.try_into()?];
        data.read_exact(&mut buf[..])?;
        println!("{buf:?}");
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_success() {
        let data: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        let packaged = Wave::package(&data).expect("Failed to package");

        let expected: Vec<u8> = vec![
            0x77, 0x61, 0x76, 0x65, 0x00, 0x00, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        assert_eq!(packaged, expected);
    }

    #[test]
    fn unpackage_success() {
        let data: Vec<u8> = vec![
            0x77, 0x61, 0x76, 0x65, 0x00, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let unpackaged = Wave::unpackage(&mut data.as_slice()).expect("Failed to unpackage");

        let expected: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(unpackaged, expected);
    }
}
