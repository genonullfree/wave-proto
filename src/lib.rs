use anyhow::Result;

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

    //fn unpackage(data: impl Read) -> Result<Vec<u8>> {
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
}
