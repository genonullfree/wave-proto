use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Result, anyhow};
use async_net::UdpSocket;
use k256::{
    EncodedPoint, PublicKey,
    ecdh::{EphemeralSecret, SharedSecret},
};
use std::io::{Read, Write};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct Wave {
    pub socket: UdpSocket,
    remote: Vec<Remote>,
    queues: Vec<Queue>,
}

#[derive(Clone)]
struct Remote {
    addr: SocketAddr,
    crypto: Option<Crypto>,
    status: Status,
}

#[derive(Clone)]
struct Queue {
    addr: SocketAddr,
    messages: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
enum Status {
    Start,
    Ecdh,
    Encrypted,
}

impl Wave {
    const WAVE: &[u8] = &[0x77, 0x61, 0x76, 0x65];
    const MAX_MSG: usize = 32768; // 32 * 1024

    pub async fn new() -> Result<Self> {
        Self::listen_at(0).await
    }

    pub async fn listen() -> Result<Self> {
        Self::listen_at(9003).await
    }

    pub async fn listen_at(port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
        let remote = Vec::new();
        let queues = Vec::new();

        Ok(Self {
            socket,
            remote,
            queues,
        })
    }

    pub fn debug_print_remotes(&self) {
        for r in &self.remote {
            println!("Connected Addr: {:?} Status: {:?}", r.addr, r.status);
        }
    }

    pub fn debug_queue_info(&self) {
        for q in &self.queues {
            println!("Queue Addr: {:?} Messages: {}", q.addr, q.messages.len());
        }
    }

    pub async fn connect(&mut self, remote: &str) -> Result<SocketAddr> {
        let addr: SocketAddr = remote.parse()?;
        self.socket.connect(addr).await?;

        // Reset any crypto
        let mut remote = self.lookup_remote(&addr)?;
        remote.crypto = None;
        remote.status = Status::Ecdh;
        self.update_remote(&remote);

        // Generate private and public keys
        let secret = Crypto::gen_secret();
        let public = Crypto::gen_pk_bytes(&secret);

        // Send and receive public keys
        self.send(&remote.addr, public.as_bytes()).await?;
        let (_source, remote_public) = self.receive().await?;

        // Calculate shared secret
        let ss = Crypto::gen_shared_secret(&remote_public, &secret)?;
        let crypto = Crypto::init(ss.raw_secret_bytes())?;
        remote.crypto = Some(crypto);
        self.update_remote(&remote);

        // Generate AES256 key and send it to the remote
        let key = Aes256Gcm::generate_key(OsRng);
        self.send(&remote.addr, key.as_slice()).await?;

        // Set the new AES256 key as the current crypto
        let crypto = Crypto::init(&key)?;
        remote.crypto = Some(crypto);
        remote.status = Status::Encrypted;
        self.update_remote(&remote);

        Ok(addr)
    }

    fn update_remote(&mut self, remote: &Remote) {
        // Remove old Remote struct if it exists
        let index = self.remote.iter().position(|x| x.addr == remote.addr);
        if let Some(index) = index {
            self.remote.remove(index);
        }
        // Push current Remote struct
        self.remote.push(remote.clone());
    }

    fn lookup_remote(&mut self, addr: &SocketAddr) -> Result<Remote> {
        // Return Remote struct if it exists for the endpoint, else create a new Remote struct
        if let Some(remote) = self.remote.iter().position(|x| x.addr == *addr) {
            let remote = self.remote.remove(remote);
            Ok(remote)
        } else {
            Ok(Remote {
                addr: *addr,
                crypto: None,
                status: Status::Start,
            })
        }
    }

    fn lookup_queue(&mut self, addr: &SocketAddr) -> Option<Queue> {
        // Return queue if it exists for the endpoint, else None
        if let Some(index) = self.queues.iter().position(|x| x.addr == *addr) {
            let queue = self.queues.remove(index);
            Some(queue)
        } else {
            None
        }
    }

    pub fn queue_clear(&mut self, addr: &SocketAddr) {
        // Find and return queue if it exists, and do nothing with it which drops it
        let _ = self.lookup_queue(addr);
    }

    pub async fn queue_send(&mut self, addr: &SocketAddr, data: &[u8]) -> Result<Vec<usize>> {
        let mut res = Vec::new();
        let mut err_queue = Vec::new();

        // Check for previous queue
        if let Some(mut queue) = self.lookup_queue(addr) {
            let mut success = true;
            // need to re-crypto if previous sends failed
            match self.connect(&addr.to_string()).await {
                Ok(_) => {}
                Err(_) => {
                    queue.messages.push(data.to_vec());
                    self.queues.push(queue);
                    return Ok(Vec::new());
                }
            }

            // Iterate through the queue
            for message in queue.messages {
                // While succeeding...
                if success {
                    // Keep sending or else add all remaining messages to the queue
                    match self.send(addr, &message).await {
                        Ok(u) => res.push(u),
                        Err(_e) => {
                            success = false;
                            err_queue.push(message);
                        }
                    }
                } else {
                    err_queue.push(message);
                }
            }
            // If we failed to send all messages, re-add queue to self.queue
            if !err_queue.is_empty() {
                err_queue.push(data.to_vec());
                queue.messages = err_queue;
                self.queues.push(queue);
                return Ok(res);
            }
        }

        // Final send for current message, or append to queue
        match self.send(addr, data).await {
            Ok(u) => res.push(u),
            Err(_e) => err_queue.push(data.to_vec()),
        };

        // Final push queue
        if !err_queue.is_empty() {
            let new_queue = Queue {
                addr: *addr,
                messages: err_queue,
            };
            self.queues.push(new_queue);
        }

        Ok(res)
    }

    pub async fn send(&mut self, addr: &SocketAddr, data: &[u8]) -> Result<usize> {
        let remote = self.lookup_remote(addr)?;
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
        let message = if let Some(crypto) = &remote.crypto {
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
        self.socket.send_to(&message, remote.addr).await?;
        self.update_remote(&remote);
        Ok(data_len)
    }

    pub async fn receive(&mut self) -> Result<(SocketAddr, Vec<u8>)> {
        // Receive packet
        let mut buf = [0u8; Self::MAX_MSG + 8];
        let (length, source) = self.socket.recv_from(&mut buf).await?;

        let mut remote = self.lookup_remote(&source)?;
        // Decrypt if crypto is in use
        let plaintext = if let Some(crypto) = &remote.crypto {
            match crypto.cipher.decrypt((&buf[..12]).into(), &buf[12..length]) {
                Ok(p) => p,
                Err(_e) => {
                    println!("Error decrypting. Attempting to reconfigure crypto.");
                    remote.crypto = None;
                    remote.status = Status::Start;
                    (buf[..length]).to_vec()
                }
            }
        } else {
            (buf[..length]).to_vec()
        };

        // Unpackage message
        let message = Self::unpackage(&mut plaintext.as_slice())?;

        // If crypto is not yet in use, setup with ECDH
        if remote.crypto.is_none() && remote.status != Status::Ecdh {
            let private = Crypto::gen_secret();
            let public = Crypto::gen_pk_bytes(&private);
            let ss = Crypto::gen_shared_secret(&message, &private)?;
            self.send(&remote.addr, public.as_bytes()).await?;
            let crypto = Crypto::init(ss.raw_secret_bytes())?;
            remote.crypto = Some(crypto);
            self.update_remote(&remote);

            // Receive generated AES256 key
            let (_source, k) = Box::pin(self.receive()).await?;
            let crypto = Crypto::init(Key::<Aes256Gcm>::from_slice(&k))?;
            remote.crypto = Some(crypto);
            remote.status = Status::Encrypted;
            self.update_remote(&remote);
            let (_, message) = Box::pin(self.receive()).await?;
            Ok((source, message))
        } else {
            self.update_remote(&remote);
            Ok((source, message))
        }
    }

    fn package(sink: &mut impl Write, data: &[u8]) -> Result<()> {
        // Package the Wave protocol
        // ---
        // 4 byte magic: b'wave'
        // 4 byte length
        // payload data[..length]
        let mut out: Vec<u8> = Self::WAVE.to_vec();
        let length: u32 = data.len().try_into()?;
        out.append(&mut length.to_be_bytes().to_vec());
        out.append(&mut data.to_vec());

        sink.write_all(&out)?;
        Ok(())
    }

    fn unpackage(source: &mut impl Read) -> Result<Vec<u8>> {
        // Unpackage the Wave protocol
        // ---
        // 4 byte magic: b'wave'
        // 4 byte length
        // payload data[..length]
        let mut check = [0u8; 4];
        source.read_exact(&mut check)?;
        if check != Self::WAVE {
            return Err(anyhow!("Protocol header mismatch!"));
        }

        source.read_exact(&mut check)?;
        let length: u32 = u32::from_be_bytes(check);
        if length as usize > Self::MAX_MSG {
            return Err(anyhow!(
                "Wave payload is too long ( {length} > {} )",
                Self::MAX_MSG
            ));
        }

        let mut buf: Vec<u8> = vec![0; length.try_into()?];
        source.read_exact(&mut buf[..])?;
        Ok(buf)
    }
}

#[derive(Clone)]
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
