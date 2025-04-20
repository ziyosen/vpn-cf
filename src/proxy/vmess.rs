use uuid::Uuid;
use aes_gcm::{Aes128Gcm, Key, Nonce};
use aes::Aes128;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Buf;
use tokio_util::codec::{FramedRead, LinesCodec};
use super::ProxyStream;

use crate::common::{
    hash, KDFSALT_CONST_AEAD_RESP_HEADER_IV, KDFSALT_CONST_AEAD_RESP_HEADER_KEY,
    KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use std::io::Cursor;
use aes::cipher::KeyInit;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm,
};
use md5::{Digest, Md5};
use sha2::Sha256;
use worker::*;

// Struct untuk ProxyStream
#[derive(Debug)]
pub struct ProxyStream<'a> {
    pub config: &'a Config,
    pub stream: FramedRead<'a, tokio::net::TcpStream, LinesCodec>,
}

#[derive(Debug)]
pub struct Config {
    pub proxy_addr: String,
    pub proxy_port: u16,
}

#[async_trait]
impl<'a> ProxyStream<'a> {
    // Fungsi dekripsi AEAD dengan UUID
    pub async fn aead_decrypt(&mut self, uuid_str: &str) -> Result<Vec<u8>, String> {
        // Validasi UUID yang diterima
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| "Invalid UUID format".to_string())?;

        // Gunakan UUID yang telah diparse sebagai bytes
        let key = &uuid.as_bytes()[..16]; // Ambil 16 bytes pertama dari UUID sebagai kunci

        let mut auth_id = [0u8; 16];
        self.stream.read_exact(&mut auth_id).await.map_err(|e| e.to_string())?;

        let mut len = [0u8; 18];
        self.stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;

        let mut nonce = [0u8; 8];
        self.stream.read_exact(&mut nonce).await.map_err(|e| e.to_string())?;

        let header_length = {
            let header_length_key = &key[..16];
            let header_length_nonce = &nonce[..12];

            let len = Aes128Gcm::new(Key::from_slice(header_length_key))
                .decrypt(Nonce::from_slice(header_length_nonce), &len)
                .map_err(|e| e.to_string())?;

            ((len[0] as u16) << 8) | (len[1] as u16)
        };

        let mut cmd = vec![0u8; (header_length + 16) as _];
        self.stream.read_exact(&mut cmd).await.map_err(|e| e.to_string())?;

        let header_payload = {
            let payload_key = &key[..16];
            let payload_nonce = &nonce[..12];

            Aes128Gcm::new(Key::from_slice(payload_key))
                .decrypt(Nonce::from_slice(payload_nonce), &cmd)
                .map_err(|e| e.to_string())?
        };

        Ok(header_payload)
    }

    // Fungsi untuk memproses data VMess
    pub async fn process_vmess(&mut self, uuid_str: &str) -> Result<(), String> {
        let decrypted_data = self.aead_decrypt(uuid_str).await?;
        let mut buf = &decrypted_data[..];

        let version = buf[0];
        if version != 1 {
            return Err("invalid version".to_string());
        }

        let iv = &buf[1..17];
        let key = &buf[17..33];

        let options = &buf[33..37];
        let cmd = buf[37];
        let is_tcp = cmd == 0x1;

        let remote_port = ((buf[38] as u16) << 8) | (buf[39] as u16);
        let remote_addr = &buf[40..44]; // Example address byte slice

        // Melakukan enkripsi payload
        let key = &key[..16];
        let iv = &iv[..16];

        // Proses header dan payload enkripsi
        let length_key = &key[..16];
        let length_iv = &iv[..12];

        let length = Aes128Gcm::new(Key::from_slice(length_key))
            .encrypt(Nonce::from_slice(length_iv), &4u16.to_be_bytes())
            .map_err(|e| e.to_string())?;

        // Menulis hasil
        self.stream.write_all(&length).await.map_err(|e| e.to_string())?;

        let payload_key = &key[..16];
        let payload_iv = &iv[..12];
        let header = {
            let header = [options[0], 0x00, 0x00, 0x00];
            Aes128Gcm::new(Key::from_slice(payload_key))
                .encrypt(Nonce::from_slice(payload_iv), &header)
                .map_err(|e| e.to_string())?
        };

        self.stream.write_all(&header).await.map_err(|e| e.to_string())?;

        Ok(())
    }
}

// Implementasi tambahan untuk ProxyStream
impl<'a> ProxyStream<'a> {
    // Fungsi dekripsi AEAD dengan key yang dihasilkan dari hash MD5
    async fn aead_decrypt(&mut self) -> Result<Vec<u8>, String> {
        let key = crate::md5!(
            &self.config.uuid.as_bytes(),
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
        );

        // +-------------------+-------------------+-------------------+
        // |     Auth ID       |   Header Length   |       Nonce       |
        // +-------------------+-------------------+-------------------+
        let mut auth_id = [0u8; 16];
        self.read_exact(&mut auth_id).await?;
        let mut len = [0u8; 18];
        self.read_exact(&mut len).await?;
        let mut nonce = [0u8; 8];
        self.read_exact(&mut nonce).await?;

        // Proses header length
        let header_length = {
            let header_length_key = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                    &auth_id,
                    &nonce,
                ],
            )[..16];
            let header_length_nonce = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                    &auth_id,
                    &nonce,
                ],
            )[..12];

            let payload = Payload {
                msg: &len,
                aad: &auth_id,
            };

            let len = Aes128Gcm::new(header_length_key.into())
                .decrypt(header_length_nonce.into(), payload)
                .map_err(|e| e.to_string())?;

            ((len[0] as u16) << 8) | (len[1] as u16)
        };

        // 16 bytes padding
        let mut cmd = vec![0u8; (header_length + 16) as _];
        self.read_exact(&mut cmd).await?;

        let header_payload = {
            let payload_key = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
                    &auth_id,
                    &nonce,
                ],
            )[..16];
            let payload_nonce = &hash::kdf(
                &key,
                &[KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &nonce],
            )[..12];

            let payload = Payload {
                msg: &cmd,
                aad: &auth_id,
            };

            Aes128Gcm::new(payload_key.into())
                .decrypt(payload_nonce.into(), payload)
                .map_err(|e| e.to_string())?
        };

        Ok(header_payload)
    }

    // Fungsi untuk memproses header VMess
    pub async fn process_vmess(&mut self) -> Result<(), String> {
        let mut buf = Cursor::new(self.aead_decrypt().await?);

        // Proses header dan payload VMess
        let version = buf.read_u8().await?;
        if version != 1 {
            return Err("invalid version".to_string());
        }

        let mut iv = [0u8; 16];
        buf.read_exact(&mut iv).await?;
        let mut key = [0u8; 16];
        buf.read_exact(&mut key).await?;

        // Ignore options untuk saat ini
        let mut options = [0u8; 4];
        buf.read_exact(&mut options).await?;

        let cmd = buf.read_u8().await?;
        let is_tcp = cmd == 0x1;

        let remote_port = {
            let mut port = [0u8; 2];
            buf.read_exact(&mut port).await?;
            ((port[0] as u16) << 8) | (port[1] as u16)
        };
        let remote_addr = crate::common::parse_addr(&mut buf).await?;

        // Encrypt payload
        let key = &crate::sha256!(&key)[..16];
        let iv = &crate::sha256!(&iv)[..16];

        // Encrypt length
        let length_key = &hash::kdf(&key, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY])[..16];
        let length_iv = &hash::kdf(&iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV])[..12];
        let length = Aes128Gcm::new(length_key.into())
            .encrypt(length_iv.into(), &4u16.to_be_bytes()[..])
            .map_err(|e| e.to_string())?;
        self.write(&length).await?;

        let payload_key = &hash::kdf(&key, &[KDFSALT_CONST_AEAD_RESP_HEADER_KEY])[..16];
        let payload_iv = &hash::kdf(&iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_IV])[..12];
        let header = {
            let header = [
                options[0], // https://github.com/v2ray/v2ray-core/blob/master/proxy/vmess/encoding/client.go#L242
                0x00, 0x00, 0x00,
            ];
            Aes128Gcm::new(payload_key.into())
                .encrypt(payload_iv.into(), &header[..])
                .map_err(|e| e.to_string())?
        };
        self.write(&header).await?;

        // Handle TCP/UDP outbound
        if is_tcp {
            let addr_pool = [
                (remote_addr.clone(), remote_port),
                (self.config.proxy_addr.clone(), self.config.proxy_port)
            ];

            for (target_addr, target_port) in addr_pool {
                if let Err(e) = self.handle_tcp_outbound(target_addr, target_port).await {
                    console_error!("error handling tcp: {}", e)
                }
            }
        } else {
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling udp: {}", e)
            }
        }

        Ok(())
    }
}
