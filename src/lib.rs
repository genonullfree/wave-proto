use anyhow::{Result, anyhow};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};

#[derive(Debug)]
pub struct Wave {
    socket: UdpSocket,
    remote: Option<SocketAddr>,
    //options: u32, // TODO: add options? encryption?
    tx: usize, // Data sent
    rx: usize, // Data received
}

impl Wave {
    const WAVE: &[u8] = &[0x77, 0x61, 0x76, 0x65];

    pub fn new() -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:9003")?;
        let remote = None;
        let tx = 0;
        let rx = 0;

        Ok(Self {
            socket,
            remote,
            tx,
            rx,
        })
    }

    pub fn new_at(port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{port}"))?;
        let remote = None;
        let tx = 0;
        let rx = 0;

        Ok(Self {
            socket,
            remote,
            tx,
            rx,
        })
    }

    pub fn connect(&mut self, remote: &str) -> Result<()> {
        let remote: SocketAddr = remote.parse()?;
        self.socket.connect(remote)?;
        self.remote = Some(remote);
        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        // Verify we have a remote
        if let Some(remote) = self.remote {
            // Package message
            let mut buf = Vec::new();
            let data_len = data.len();
            Self::package(&mut buf, data)?;
            // Send packet
            self.socket.send_to(&buf, &remote)?;

            // Update counter
            self.tx += data_len;

            Ok(0)
        } else {
            Err(anyhow!("Remote address is not set!"))
        }
    }

    pub fn receive(&mut self) -> Result<Vec<u8>> {
        // Receive packet
        let mut buf = [0u8; 65535];
        let (_length, source) = self.socket.recv_from(&mut buf)?;

        // Verify source
        if let Some(remote) = self.remote {
            if remote != source {
                return Err(anyhow!("Received packet from non-remote source"));
            }
        } else {
            self.remote = Some(source);
        }

        // Unpackage message
        let message = Self::unpackage(&mut buf.as_slice())?;

        // Update counter
        self.rx += message.len();

        Ok(message)
    }

    fn package(sink: &mut impl Write, data: &[u8]) -> Result<()> {
        let mut out: Vec<u8> = Self::WAVE.to_vec();
        let length: u32 = data.len().try_into()?;
        out.append(&mut length.to_be_bytes().to_vec());
        out.append(&mut data.to_vec());

        sink.write_all(&mut out)?;
        Ok(())
    }

    fn unpackage(source: &mut impl Read) -> Result<Vec<u8>> {
        let mut check = [0u8; 4];
        source.read_exact(&mut check)?;
        if &check != Self::WAVE {
            return Err(anyhow!("Protocol header mismatch!"));
        }

        source.read_exact(&mut check)?;
        let length: u32 = u32::from_be_bytes(check);

        let mut buf: Vec<u8> = vec![0; length.try_into()?];
        source.read_exact(&mut buf[..])?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_success() {
        let mut sink: Vec<u8> = Vec::new();
        let data: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        Wave::package(&mut sink, &data).expect("Failed to package");

        let expected: Vec<u8> = vec![
            0x77, 0x61, 0x76, 0x65, 0x00, 0x00, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        assert_eq!(sink, expected);
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
