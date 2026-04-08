use crate::consts::{Action, Command, MsgTypes, SecretSessionVersion, Status};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct RenamedPasswordEntry {
    pub username: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct PasswordEntry {
    pub USR: String,
    pub sites: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub PWD: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct TOTPEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub username: String,
    pub source: String,
    pub domain: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Entry {
    Password(PasswordEntry),
    TOTP(TOTPEntry),
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Payload {
    pub STATUS: Status,
    pub Entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct Capabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canFillOneTimeCodes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanForOTPURI: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shouldUseBase64: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operatingSystem: Option<OperatingSystem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct OperatingSystem {
    pub name: String,
    pub majorVersion: u32,
    pub minorVersion: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtoVersion {
    Single(SecretSessionVersion),
    Array(Vec<SecretSessionVersion>),
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct PAKEMessage {
    pub TID: String,
    pub MSG: MsgTypes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub A: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub B: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub M: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub HAMK: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub VER: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub PROTO: Option<ProtoVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ErrCode: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PakeField {
    Message(PAKEMessage),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SMSGPayload {
    pub TID: String,
    pub SDATA: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SmsgField {
    Object(SMSGPayload),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SMSG {
    pub SMSG: SmsgField,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SRPHandshakeMessage {
    pub QID: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub HSTBRSR: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub PAKE: Option<PakeField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub SMSG: Option<SmsgField>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum MessagePayloadField {
    Handshake(SRPHandshakeMessage),
    String(String),
    Smsg(SMSG),
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct Message {
    pub cmd: Command,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<MessagePayloadField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<MessagePayloadField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setUpTOTPPageURL: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setUpTOTPURI: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tabId: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frameId: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct ManifestConfig {
    pub name: String,
    pub description: String,
    pub path: String,
    pub r#type: String,
    #[serde(
        alias = "allowedOrigins",
        alias = "allowed_origins",
        alias = "allowed_extensions"
    )]
    pub allowedOrigins: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct ApplePWConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sharedKey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct SRPValues {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sharedKey: Option<num_bigint::BigUint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clientPrivateKey: Option<num_bigint::BigUint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<num_bigint::BigUint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serverPublicKey: Option<num_bigint::BigUint>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct EncryptPayload {
    pub ACT: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub URL: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub USR: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub TYPE: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frameURLs: Option<Vec<String>>,
}
