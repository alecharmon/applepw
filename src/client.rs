use crate::consts::{Action, Command, MsgTypes, SecretSessionVersion};
use crate::srp::SRPSession;
use crate::types::{
    EncryptPayload, Message, MessagePayloadField, PAKEMessage, PakeField, Payload, SMSG,
    SMSGPayload, SRPHandshakeMessage, SmsgField,
};
use crate::utils::{read_bigint, read_config, to_base64, to_buffer, write_config};
use anyhow::{Result, anyhow};
use std::net::UdpSocket;
use std::time::SystemTime;

const BROWSER_NAME: &str = "Arc";
const VERSION: &str = "1.0";

pub struct ApplePasswordManager {
    pub session: SRPSession,
    pub remote_port: Option<u16>,
    pub challenge_timestamp: u64,
}

impl Default for ApplePasswordManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplePasswordManager {
    pub fn new() -> Self {
        let mut session = SRPSession::new(true);
        let (username, shared_key, port) = read_config().unwrap_or((None, None, None));

        let mut values = crate::types::SRPValues::default();
        if let Some(u) = username {
            values.username = Some(u);
        }
        if let Some(sk) = shared_key {
            values.sharedKey = Some(sk);
        }
        session.update_with_values(values);

        Self {
            session,
            remote_port: port,
            challenge_timestamp: 0,
        }
    }

    pub fn send_message(&self, message_content: &Message) -> Result<serde_json::Value> {
        let (_, _, port) = read_config().unwrap_or((None, None, None));
        let port = port.ok_or_else(|| anyhow!("Daemon port not found in config"))?;
        let socket = UdpSocket::bind("127.0.0.1:0")?;

        let content = serde_json::to_vec(message_content)?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.send_to(&content, format!("127.0.0.1:{}", port))?;

        let mut buf = [0u8; 65535];
        let (amt, _) = match socket.recv_from(&mut buf) {
            Ok(res) => res,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to receive response from daemon on port {}: {}",
                    port,
                    e
                ));
            }
        };
        let response_str = std::str::from_utf8(&buf[..amt])?;

        let response: serde_json::Value = serde_json::from_str(response_str)?;
        if response.get("error").is_some() {
            return Err(anyhow!("{}", response["error"]));
        }

        Ok(response)
    }

    pub fn decrypt_payload(&self, payload: &SMSG) -> Result<Payload> {
        let smsg_obj = match &payload.SMSG {
            SmsgField::Object(obj) => obj,
            SmsgField::String(s) => {
                let parsed: SMSGPayload = serde_json::from_str(s)?;
                return self.decrypt_payload(&SMSG {
                    SMSG: SmsgField::Object(parsed),
                });
            }
        };

        if smsg_obj.TID != self.session.username {
            return Err(anyhow!(
                "Invalid server response: destined to another session"
            ));
        }

        let sdata = self.session.deserialize(&smsg_obj.SDATA)?;
        let decrypted = self.session.decrypt(&sdata)?;

        let response: Payload = serde_json::from_slice(&decrypted)?;
        Ok(response)
    }

    pub fn get_capabilities(&self) -> Result<serde_json::Value> {
        let msg = Message {
            cmd: Command::GetCapabilities,
            payload: None,
            msg: None,
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
            url: None,
            tabId: None,
            frameId: None,
        };

        self.send_message(&msg)
    }

    pub fn normalize_url(&self, url: &str) -> String {
        if url.is_empty() {
            return "".to_string();
        }
        if url.contains("://") {
            url.to_string()
        } else {
            format!("https://{}", url)
        }
    }

    pub fn request_challenge(&mut self) -> Result<(num_bigint::BigUint, num_bigint::BigUint)> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        if self.challenge_timestamp >= now.saturating_sub(5) {
            return Err(anyhow!("Requested challenge too soon"));
        }
        self.challenge_timestamp = now;

        let pake_msg = PAKEMessage {
            TID: self.session.username.clone(),
            MSG: MsgTypes::ClientKeyExchange,
            A: Some(
                self.session
                    .serialize(&to_buffer(&self.session.client_public_key()), true),
            ),
            VER: Some(VERSION.to_string()),
            PROTO: Some(crate::types::ProtoVersion::Array(vec![
                SecretSessionVersion::SrpWithRfcVerification,
            ])),
            s: None,
            B: None,
            M: None,
            HAMK: None,
            ErrCode: None,
        };
        let pake_json = serde_json::to_string(&pake_msg)?;
        let pake_b64 = to_base64(pake_json.as_bytes());

        let msg = Message {
            cmd: Command::Handshake,
            payload: None,
            msg: Some(MessagePayloadField::Handshake(SRPHandshakeMessage {
                QID: "m0".to_string(),
                HSTBRSR: Some(BROWSER_NAME.to_string()),
                PAKE: Some(PakeField::String(pake_b64)),
                SMSG: None,
            })),
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
            url: None,
            tabId: None,
            frameId: None,
        };

        let response = self.send_message(&msg)?;
        let payload_b64 = response["payload"]["PAKE"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing PAKE in payload"))?;
        let payload_bytes = crate::utils::from_base64(payload_b64)?;
        let pake: PAKEMessage = serde_json::from_slice(&payload_bytes)?;

        if pake.TID != self.session.username {
            return Err(anyhow!("Invalid server hello: destined to another session"));
        }

        if pake.ErrCode.unwrap_or(0) != 0 {
            return Err(anyhow!(
                "Invalid server hello: error code {}",
                pake.ErrCode.unwrap()
            ));
        }

        if pake.MSG != MsgTypes::ServerKeyExchange {
            return Err(anyhow!("Invalid server hello: unexpected message"));
        }

        let proto = match pake.PROTO.as_ref() {
            Some(crate::types::ProtoVersion::Single(p)) => *p,
            Some(crate::types::ProtoVersion::Array(arr)) => {
                *arr.first().ok_or_else(|| anyhow!("Missing PROTO"))?
            }
            None => return Err(anyhow!("Missing PROTO")),
        };
        if proto != SecretSessionVersion::SrpWithRfcVerification {
            return Err(anyhow!("Invalid server hello: unsupported protocol"));
        }

        if pake.VER.as_deref().unwrap_or(VERSION) != VERSION {
            return Err(anyhow!("Invalid server hello: unsupported version"));
        }

        let server_public_key = read_bigint(&self.session.deserialize(pake.B.as_ref().unwrap())?);
        let salt = read_bigint(&self.session.deserialize(pake.s.as_ref().unwrap())?);

        self.session
            .set_server_public_key(server_public_key.clone(), salt.clone())?;

        Ok((server_public_key, salt))
    }

    pub fn verify_challenge(&mut self, password: &str) -> Result<()> {
        let new_key = self.session.set_shared_key(password)?;
        let m = self.session.compute_m()?;

        let pake_msg = PAKEMessage {
            TID: self.session.username.clone(),
            MSG: MsgTypes::ClientVerification,
            M: Some(self.session.serialize(&m, false)),
            A: None,
            s: None,
            B: None,
            HAMK: None,
            VER: None,
            PROTO: None,
            ErrCode: None,
        };
        let pake_json = serde_json::to_string(&pake_msg)?;
        let pake_b64 = to_base64(pake_json.as_bytes());

        let msg = Message {
            cmd: Command::Handshake,
            payload: None,
            msg: Some(MessagePayloadField::Handshake(SRPHandshakeMessage {
                QID: "m2".to_string(),
                HSTBRSR: Some(BROWSER_NAME.to_string()),
                PAKE: Some(PakeField::String(pake_b64)),
                SMSG: None,
            })),
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
            url: None,
            tabId: None,
            frameId: None,
        };

        let response = self.send_message(&msg)?;
        let payload_b64 = response["payload"]["PAKE"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing PAKE in payload"))?;
        let payload_bytes = crate::utils::from_base64(payload_b64)?;
        let pake: PAKEMessage = serde_json::from_slice(&payload_bytes)?;

        if pake.TID != self.session.username {
            return Err(anyhow!(
                "Invalid server verification: destined to another session"
            ));
        }

        if pake.MSG != MsgTypes::ServerVerification {
            return Err(anyhow!("Invalid server verification: unexpected message"));
        }

        if let Some(err) = pake.ErrCode {
            match err {
                0 => {}
                1 => return Err(anyhow!("Incorrect challenge PIN")),
                _ => return Err(anyhow!("Invalid server verification: error code {}", err)),
            }
        }

        let hmac = self.session.compute_hmac(&m)?;
        let server_hmac = read_bigint(&self.session.deserialize(pake.HAMK.as_ref().unwrap())?);

        if server_hmac != read_bigint(&hmac) {
            return Err(anyhow!("Invalid server verification: HAMK mismatch"));
        }

        println!("Challenge verified, updating config");
        write_config(
            Some(self.session.username.clone()),
            Some(new_key),
            self.remote_port,
        )?;

        Ok(())
    }

    pub fn get_login_names_for_url(&self, url: &str) -> Result<Payload> {
        let full_url = self.normalize_url(url);
        let encrypt_url = url.to_string();
        let sdata_encrypted = self.session.encrypt(&serde_json::to_vec(&EncryptPayload {
            ACT: Action::GhostSearch,
            URL: Some(encrypt_url),
            USR: None,
            TYPE: Some("password".to_string()),
            frameURLs: Some(vec![full_url.clone()]),
        })?)?;

        let sdata = self.session.serialize(&sdata_encrypted, true);

        let msg = Message {
            cmd: Command::GetLoginNamesForUrl,
            url: Some(full_url),
            tabId: Some(0),
            frameId: Some(0),
            payload: Some(MessagePayloadField::String(serde_json::to_string(
                &SRPHandshakeMessage {
                    QID: "CmdGetLoginNames4URL".to_string(),
                    SMSG: Some(SmsgField::Object(SMSGPayload {
                        TID: self.session.username.clone(),
                        SDATA: sdata,
                    })),
                    HSTBRSR: None,
                    PAKE: None,
                },
            )?)),
            msg: None,
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
        };

        let response = self.send_message(&msg)?;
        let smsg_payload: SMSG =
            serde_json::from_str(response["payload"].as_str().unwrap_or_default())
                .or_else(|_| serde_json::from_value(response["payload"].clone()))?;
        self.decrypt_payload(&smsg_payload)
    }

    pub fn get_password_for_url(&self, url: &str, login_name: &str) -> Result<Payload> {
        let full_url = self.normalize_url(url);
        let sdata_encrypted = self.session.encrypt(&serde_json::to_vec(&EncryptPayload {
            ACT: Action::Search,
            URL: Some(full_url.clone()),
            USR: Some(login_name.to_string()),
            TYPE: None,
            frameURLs: None,
        })?)?;

        let sdata = self.session.serialize(&sdata_encrypted, true);

        let msg = Message {
            cmd: Command::GetPasswordForLoginName,
            url: Some(full_url),
            tabId: Some(0),
            frameId: Some(0),
            payload: Some(MessagePayloadField::String(serde_json::to_string(
                &SRPHandshakeMessage {
                    QID: "CmdGetPassword4LoginName".to_string(),
                    SMSG: Some(SmsgField::Object(SMSGPayload {
                        TID: self.session.username.clone(),
                        SDATA: sdata,
                    })),
                    HSTBRSR: None,
                    PAKE: None,
                },
            )?)),
            msg: None,
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
        };

        let response = self.send_message(&msg)?;
        let smsg_payload: SMSG =
            serde_json::from_str(response["payload"].as_str().unwrap_or_default())
                .or_else(|_| serde_json::from_value(response["payload"].clone()))?;
        self.decrypt_payload(&smsg_payload)
    }

    pub fn get_otp_for_url(&self, url: &str) -> Result<Payload> {
        let full_url = self.normalize_url(url);
        let sdata_encrypted = self.session.encrypt(&serde_json::to_vec(&EncryptPayload {
            ACT: Action::Search,
            URL: Some(full_url.clone()),
            USR: None,
            TYPE: Some("oneTimeCodes".to_string()),
            frameURLs: Some(vec![full_url.clone()]),
        })?)?;

        let sdata = self.session.serialize(&sdata_encrypted, true);

        let msg = Message {
            cmd: Command::DidFillOneTimeCode,
            url: Some(full_url),
            tabId: Some(0),
            frameId: Some(0),
            payload: Some(MessagePayloadField::String(serde_json::to_string(
                &SRPHandshakeMessage {
                    QID: "CmdDidFillOneTimeCode".to_string(),
                    SMSG: Some(SmsgField::Object(SMSGPayload {
                        TID: self.session.username.clone(),
                        SDATA: sdata,
                    })),
                    HSTBRSR: None,
                    PAKE: None,
                },
            )?)),
            msg: None,
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
        };

        let response = self.send_message(&msg)?;
        let smsg_payload: SMSG =
            serde_json::from_str(response["payload"].as_str().unwrap_or_default())
                .or_else(|_| serde_json::from_value(response["payload"].clone()))?;
        self.decrypt_payload(&smsg_payload)
    }

    pub fn list_otp_for_url(&self, url: &str) -> Result<Payload> {
        let full_url = self.normalize_url(url);
        let sdata_encrypted = self.session.encrypt(&serde_json::to_vec(&EncryptPayload {
            ACT: Action::Search,
            URL: Some(full_url.clone()),
            USR: None,
            TYPE: Some("oneTimeCodes".to_string()),
            frameURLs: Some(vec![full_url.clone()]),
        })?)?;

        let sdata = self.session.serialize(&sdata_encrypted, true);

        let msg = Message {
            cmd: Command::GetOneTimeCodes,
            url: Some(full_url),
            tabId: Some(0),
            frameId: Some(0),
            payload: Some(MessagePayloadField::String(serde_json::to_string(
                &SRPHandshakeMessage {
                    QID: "CmdGetOneTimeCodes".to_string(),
                    SMSG: Some(SmsgField::Object(SMSGPayload {
                        TID: self.session.username.clone(),
                        SDATA: sdata,
                    })),
                    HSTBRSR: None,
                    PAKE: None,
                },
            )?)),
            msg: None,
            capabilities: None,
            setUpTOTPPageURL: None,
            setUpTOTPURI: None,
        };

        let response = self.send_message(&msg)?;
        let smsg_payload: SMSG =
            serde_json::from_str(response["payload"].as_str().unwrap_or_default())
                .or_else(|_| serde_json::from_value(response["payload"].clone()))?;
        self.decrypt_payload(&smsg_payload)
    }
}
