use serde_repr::{Deserialize_repr, Serialize_repr};

pub const VERSION: &str = "1.0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum Command {
    End = 0,
    Unused = 1,
    Handshake = 2,
    SetIconAndTitle = 3,
    GetLoginNamesForUrl = 4,
    GetPasswordForLoginName = 5,
    SetPasswordForLoginNameAndUrl = 6,
    NewAccountForUrl = 7,
    TabEvent = 8,
    PasswordsDisabled = 9,
    ReloginNeeded = 10,
    LaunchIcloudPasswords = 11,
    IcloudPasswordsStateChange = 12,
    LaunchPasswordsApp = 13,
    GetCapabilities = 14,
    OneTimeCodeAvailable = 15,
    GetOneTimeCodes = 16,
    DidFillOneTimeCode = 17,
    OpenUrlInSafari = 1984,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum SecretSessionVersion {
    SrpWithOldVerification = 0,
    SrpWithRfcVerification = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum MsgTypes {
    ClientKeyExchange = 0,
    ServerKeyExchange = 1,
    ClientVerification = 2,
    ServerVerification = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum Action {
    Unknown = -1,
    Delete = 0,
    Update = 1,
    Search = 2,
    AddNew = 3,
    MaybeAdd = 4,
    GhostSearch = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum Status {
    Success = 0,
    GenericError = 1,
    InvalidParam = 2,
    NoResults = 3,
    FailedToDelete = 4,
    FailedToUpdate = 5,
    InvalidMessageFormat = 6,
    DuplicateItem = 7,
    UnknownAction = 8,
    InvalidSession = 9,
    ServerError = 100,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Status::Success => "Operation successful",
            Status::GenericError => "A generic error occurred",
            Status::InvalidParam => "Invalid parameter provided",
            Status::NoResults => "No results found",
            Status::FailedToDelete => "Failed to delete item",
            Status::FailedToUpdate => "Failed to update item",
            Status::InvalidMessageFormat => "Invalid message format",
            Status::DuplicateItem => "Duplicate item found",
            Status::UnknownAction => "Unknown action requested",
            Status::InvalidSession => "Invalid session, reauthenticate with `applepw auth`",
            Status::ServerError => "Server error",
        };
        write!(f, "{}", msg)
    }
}
