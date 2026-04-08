use crate::types::SRPValues;
use crate::utils::{from_base64, pad, random_bytes, read_bigint, sha256, to_base64, to_buffer};
use aes_gcm::{
    aead::{Aead, KeyInit},
    AesGcm,
};
use aes::Aes128;
use typenum::U16;
use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use num_traits::Num;

lazy_static::lazy_static! {
    static ref GROUP_PRIME: BigUint = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        16
    ).unwrap();
}

const GROUP_PRIME_BYTES: usize = 3072 >> 3;
const GROUP_GENERATOR: u32 = 5;

type Aes128Gcm16 = AesGcm<Aes128, U16>;

pub struct SRPSession {
    pub should_use_base64: bool,
    pub username: String, // Hex or Base64 String
    pub client_private_key: BigUint,
    pub server_public_key: Option<BigUint>,
    pub salt: Option<BigUint>,
    pub shared_key: Option<BigUint>,
}

impl SRPSession {
    pub fn new(should_use_base64: bool) -> Self {
        let username_bytes = random_bytes(16);
        let client_private_key = read_bigint(&random_bytes(32));

        let mut session = Self {
            should_use_base64,
            username: String::new(),
            client_private_key,
            server_public_key: None,
            salt: None,
            shared_key: None,
        };

        session.username = session.serialize(&username_bytes, true);
        session
    }

    pub fn update_with_values(&mut self, values: SRPValues) {
        if let Some(u) = values.username {
            self.username = u;
        }
        if let Some(s) = values.sharedKey {
            self.shared_key = Some(s);
        }
        if let Some(c) = values.clientPrivateKey {
            self.client_private_key = c;
        }
        if let Some(salt) = values.salt {
            self.salt = Some(salt);
        }
        if let Some(sp) = values.serverPublicKey {
            self.server_public_key = Some(sp);
        }
    }

    pub fn return_values(&self) -> SRPValues {
        SRPValues {
            username: Some(self.username.clone()),
            sharedKey: self.shared_key.clone(),
            clientPrivateKey: Some(self.client_private_key.clone()),
            salt: self.salt.clone(),
            serverPublicKey: self.server_public_key.clone(),
        }
    }

    pub fn client_public_key(&self) -> BigUint {
        BigUint::from(GROUP_GENERATOR).modpow(&self.client_private_key, &GROUP_PRIME)
    }

    pub fn serialize(&self, data: &[u8], prefix: bool) -> String {
        if self.should_use_base64 {
            to_base64(data)
        } else {
            let hex_str = hex::encode(data);
            if prefix {
                format!("0x{}", hex_str)
            } else {
                hex_str
            }
        }
    }

    pub fn deserialize(&self, data: &str) -> Result<Vec<u8>> {
        if self.should_use_base64 {
            from_base64(data)
        } else {
            let s = data.strip_prefix("0x").unwrap_or(data);
            Ok(hex::decode(s)?)
        }
    }

    pub fn set_server_public_key(
        &mut self,
        server_public_key: BigUint,
        salt: BigUint,
    ) -> Result<()> {
        if &server_public_key % &*GROUP_PRIME == BigUint::from(0u32) {
            return Err(anyhow!("Invalid server hello: invalid public key"));
        }
        self.server_public_key = Some(server_public_key);
        self.salt = Some(salt);
        Ok(())
    }

    pub fn set_shared_key(&mut self, password: &str) -> Result<BigUint> {
        let server_public_key = self
            .server_public_key
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid session state: missing server public key"))?;
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid session state: missing salt"))?;

        let client_pub_key = self.client_public_key();

        let mut u_input = pad(&to_buffer(&client_pub_key), GROUP_PRIME_BYTES);
        u_input.extend_from_slice(&pad(&to_buffer(server_public_key), GROUP_PRIME_BYTES));
        let public_keys_hash = read_bigint(&sha256(&u_input));

        let mut k_input = to_buffer(&GROUP_PRIME);
        k_input.extend_from_slice(&pad(
            &to_buffer(&BigUint::from(GROUP_GENERATOR)),
            GROUP_PRIME_BYTES,
        ));
        let multiplier = read_bigint(&sha256(&k_input));

        let mut x_input = to_buffer(salt);
        let password_hash = sha256(format!("{}:{}", self.username, password).as_bytes());
        x_input.extend_from_slice(&password_hash);
        let salted_password = read_bigint(&sha256(&x_input));

        let term1 = (&multiplier
            * BigUint::from(GROUP_GENERATOR).modpow(&salted_password, &GROUP_PRIME))
            % &*GROUP_PRIME;

        let base = if server_public_key >= &term1 {
            server_public_key - &term1
        } else {
            &*GROUP_PRIME - (&term1 - server_public_key)
        };

        let exponent = &self.client_private_key + (&public_keys_hash * &salted_password);

        let premaster_secret = base.modpow(&exponent, &GROUP_PRIME);

        let shared_key = read_bigint(&sha256(&to_buffer(&premaster_secret)));
        self.shared_key = Some(shared_key.clone());
        Ok(shared_key)
    }

    pub fn compute_m(&self) -> Result<Vec<u8>> {
        let server_public_key = self
            .server_public_key
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid session state: missing server public key"))?;
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid session state: missing salt"))?;
        let shared_key = self
            .shared_key
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid session state: missing shared key"))?;

        let n_hash = sha256(&to_buffer(&GROUP_PRIME));
        let g_hash = sha256(&pad(
            &to_buffer(&BigUint::from(GROUP_GENERATOR)),
            GROUP_PRIME_BYTES,
        ));
        let i_hash = sha256(self.username.as_bytes());

        let mut xor_hash = vec![0u8; 32];
        for i in 0..32 {
            xor_hash[i] = n_hash[i] ^ g_hash[i];
        }

        let mut m_input = xor_hash;
        m_input.extend_from_slice(&i_hash);
        m_input.extend_from_slice(&to_buffer(salt));
        m_input.extend_from_slice(&to_buffer(&self.client_public_key()));
        m_input.extend_from_slice(&to_buffer(server_public_key));
        m_input.extend_from_slice(&to_buffer(shared_key));

        Ok(sha256(&m_input))
    }

    pub fn compute_hmac(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shared_key = self
            .shared_key
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid session state: missing shared key"))?;

        let mut input = to_buffer(&self.client_public_key());
        input.extend_from_slice(data);
        input.extend_from_slice(&to_buffer(shared_key));

        Ok(sha256(&input))
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shared_key = self.shared_key.as_ref().ok_or_else(|| {
            anyhow!("Missing encryption key. Reauthenticate with `applepw auth`.")
        })?;

        let mut key_bytes = to_buffer(shared_key);
        if key_bytes.len() < 16 {
            let mut padded = vec![0u8; 16 - key_bytes.len()];
            padded.extend(key_bytes);
            key_bytes = padded;
        } else {
            key_bytes.truncate(16);
        }
        let key = &key_bytes[0..16];

        let cipher = Aes128Gcm16::new_from_slice(key)?;

        let iv = random_bytes(16);
        let nonce = aes_gcm::aead::Nonce::<Aes128Gcm16>::from_slice(&iv);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        // Client appends IV to the END
        let mut result = ciphertext;
        result.extend_from_slice(&iv);
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shared_key = self.shared_key.as_ref().ok_or_else(|| {
            anyhow!("Missing encryption key. Reauthenticate with `applepw auth`.")
        })?;

        if data.len() < 16 {
            return Err(anyhow!("Invalid encrypted data"));
        }

        // Native host sends IV at the START of the buffer
        let iv = &data[0..16];
        let ciphertext = &data[16..];

        let mut key_bytes = to_buffer(shared_key);
        if key_bytes.len() < 16 {
            let mut padded = vec![0u8; 16 - key_bytes.len()];
            padded.extend(key_bytes);
            key_bytes = padded;
        } else {
            key_bytes.truncate(16);
        }
        let key = &key_bytes[0..16];

        let cipher = Aes128Gcm16::new_from_slice(key)?;
        let nonce = aes_gcm::aead::Nonce::<Aes128Gcm16>::from_slice(iv);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        Ok(plaintext)
    }
}
