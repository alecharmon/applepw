use crate::types::ApplePWConfig;
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

pub fn data_path() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".applepw");
    path
}

pub fn to_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn from_base64(data: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::STANDARD.decode(data)?)
}

pub fn read_bigint(buffer: &[u8]) -> BigUint {
    BigUint::from_bytes_be(buffer)
}

pub fn to_buffer(data: &BigUint) -> Vec<u8> {
    data.to_bytes_be()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn pad(buffer: &[u8], length: usize) -> Vec<u8> {
    let mut array = vec![0u8; length];
    if buffer.len() <= length {
        let start = length - buffer.len();
        array[start..].copy_from_slice(buffer);
    } else {
        array.copy_from_slice(&buffer[0..length]);
    }
    array
}

pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut array = vec![0u8; count];
    rand::thread_rng().fill_bytes(&mut array);
    array
}

pub fn clear_config() -> Result<()> {
    let mut path = data_path();
    path.push("config.toml");
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn write_config(
    username: Option<String>,
    shared_key: Option<BigUint>,
    port: Option<u16>,
) -> Result<()> {
    let dir_path = data_path();
    fs::create_dir_all(&dir_path)?;

    let mut path = dir_path;
    path.push("config.toml");

    let mut existing_config: ApplePWConfig = if path.exists() {
        let content = fs::read_to_string(&path)?;
        toml::from_str(&content).unwrap_or_default()
    } else {
        ApplePWConfig::default()
    };

    if let Some(u) = username {
        existing_config.username = Some(u);
    }
    if let Some(k) = shared_key {
        existing_config.sharedKey = Some(to_base64(&to_buffer(&k)));
    }
    if let Some(p) = port {
        existing_config.port = Some(p);
    } else if existing_config.port.is_none() {
        existing_config.port = Some(10000);
    }

    let serialized = toml::to_string(&existing_config)?;
    let mut file = fs::File::create(&path)?;
    use std::io::Write;
    file.write_all(serialized.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn read_config() -> Result<(Option<String>, Option<BigUint>, Option<u16>)> {
    let mut path = data_path();
    path.push("config.toml");

    if !path.exists() {
        return Err(anyhow!("No existing keys. Please login first."));
    }

    let content = fs::read_to_string(&path)?;
    let config: ApplePWConfig = toml::from_str(&content)?;

    let shared_key = if let Some(sk) = config.sharedKey {
        Some(read_bigint(&from_base64(&sk)?))
    } else {
        None
    };

    Ok((config.username, shared_key, config.port))
}
