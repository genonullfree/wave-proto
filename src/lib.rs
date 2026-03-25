use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Result, anyhow};
use k256::{
    EncodedPoint, PublicKey,
    ecdh::{EphemeralSecret, SharedSecret},
};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};

pub struct Wave {
    socket: UdpSocket,
    remote: Option<SocketAddr>,
    crypto: Option<Crypto>,
    status: Status,
    tx: usize, // Data sent
    rx: usize, // Data received
}

#[derive(Debug, PartialEq)]
enum Status {
    Start,
    Ecdh,
    Encrypted,
}

impl Wave {
    const WAVE: &[u8] = &[0x77, 0x61, 0x76, 0x65];
    const MAX_MSG: usize = 32768; // 32 * 1024

    pub fn new() -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:9003")?;
        let remote = None;
        let crypto = None;
        let status = Status::Start;
        let tx = 0;
        let rx = 0;

        Ok(Self {
            socket,
            remote,
            crypto,
            status,
            tx,
            rx,
        })
    }

    pub fn new_at(port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{port}"))?;
        let remote = None;
        let crypto = None;
        let status = Status::Start;
        let tx = 0;
        let rx = 0;

        Ok(Self {
            socket,
            remote,
            crypto,
            status,
            tx,
            rx,
        })
    }

    pub fn connect(&mut self, remote: &str) -> Result<()> {
        let remote: SocketAddr = remote.parse()?;
        self.socket.connect(remote)?;
        self.remote = Some(remote);

        self.status = Status::Ecdh;
        let secret = Crypto::gen_secret();
        let public = Crypto::gen_pk_bytes(&secret);

        self.send(public.as_bytes())?;
        let remote_public = self.receive()?;
        let ss = Crypto::gen_shared_secret(&remote_public, &secret)?;
        let crypto = Crypto::init(ss.raw_secret_bytes())?;
        self.crypto = Some(crypto);

        // Set generated AES256 key
        let key = Aes256Gcm::generate_key(OsRng);
        self.send(key.as_slice())?;
        let crypto = Crypto::init(&key)?;
        self.crypto = Some(crypto);
        self.status = Status::Encrypted;

        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        // Verify we have a remote
        if let Some(remote) = self.remote {
            // Package message
            let mut buf = Vec::new();
            let data_len = data.len();
            if data_len > Self::MAX_MSG {
                return Err(anyhow!(
                    "Message is too long ( {data_len} > {} )",
                    Self::MAX_MSG
                ));
            }

            // Package up message
            Self::package(&mut buf, data)?;

            // Encrypt if crypto is in use
            let message = if let Some(crypto) = &self.crypto {
                let nonce = Crypto::nonce();
                let mut ciphertext = crypto
                    .cipher
                    .encrypt((&nonce).into(), &*buf)
                    .expect("Crypto error encrypting");
                let mut message = nonce.to_vec();
                message.append(&mut ciphertext);
                message
            } else {
                buf
            };

            // Send packet
            self.socket.send_to(&message, remote)?;

            // Update counter
            self.tx += data_len;

            Ok(0)
        } else {
            Err(anyhow!("Remote address is not set!"))
        }
    }

    pub fn receive(&mut self) -> Result<Vec<u8>> {
        // Receive packet
        let mut buf = [0u8; Self::MAX_MSG + 8];
        let (length, source) = self.socket.recv_from(&mut buf)?;

        // Verify source
        if let Some(remote) = self.remote {
            // If we have not seen this source before, remove our crypto and set this as the new
            // source
            if remote != source {
                self.crypto = None;
                self.remote = Some(source);
            }
        } else {
            self.remote = Some(source);
        }

        // Decrypt if crypto is in use
        let plaintext = if let Some(crypto) = &self.crypto {
            crypto
                .cipher
                .decrypt((&buf[..12]).into(), &buf[12..length])
                .expect("Crypto error decrypting")
        } else {
            (buf[..length]).to_vec()
        };

        // Unpackage message
        let message = Self::unpackage(&mut plaintext.as_slice())?;

        // If crypto is not yet in use, setup with ECDH
        if self.crypto.is_none() && self.status != Status::Ecdh {
            let private = Crypto::gen_secret();
            let public = Crypto::gen_pk_bytes(&private);
            let ss = Crypto::gen_shared_secret(&message, &private)?;
            self.send(public.as_bytes())?;
            let crypto = Crypto::init(ss.raw_secret_bytes())?;
            self.crypto = Some(crypto);

            // Receive generated AES256 key
            let k = self.receive()?;
            let crypto = Crypto::init(Key::<Aes256Gcm>::from_slice(&k))?;
            self.crypto = Some(crypto);
            self.status = Status::Encrypted;
        }

        // Update counter
        self.rx += message.len();

        Ok(message)
    }

    fn package(sink: &mut impl Write, data: &[u8]) -> Result<()> {
        let mut out: Vec<u8> = Self::WAVE.to_vec();
        let length: u32 = data.len().try_into()?;
        out.append(&mut length.to_be_bytes().to_vec());
        out.append(&mut data.to_vec());

        sink.write_all(&out)?;
        Ok(())
    }

    fn unpackage(source: &mut impl Read) -> Result<Vec<u8>> {
        let mut check = [0u8; 4];
        source.read_exact(&mut check)?;
        if check != Self::WAVE {
            return Err(anyhow!("Protocol header mismatch!"));
        }

        source.read_exact(&mut check)?;
        let length: u32 = u32::from_be_bytes(check);

        let mut buf: Vec<u8> = vec![0; length.try_into()?];
        source.read_exact(&mut buf[..])?;
        Ok(buf)
    }
}

struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    pub fn init(key: &Key<Aes256Gcm>) -> Result<Self> {
        let cipher = Aes256Gcm::new(key);
        Ok(Self { cipher })
    }

    pub fn nonce() -> [u8; 12] {
        Aes256Gcm::generate_nonce(&mut OsRng).into()
    }

    pub fn gen_secret() -> EphemeralSecret {
        EphemeralSecret::random(&mut OsRng)
    }

    pub fn gen_pk_bytes(secret: &EphemeralSecret) -> EncodedPoint {
        EncodedPoint::from(secret.public_key())
    }

    pub fn gen_shared_secret(input: &[u8], secret: &EphemeralSecret) -> Result<SharedSecret> {
        let remote_public = PublicKey::from_sec1_bytes(input)?;
        Ok(secret.diffie_hellman(&remote_public))
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
