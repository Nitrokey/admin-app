use core::{
    fmt::{self, Display, Formatter, Write as _},
    str::FromStr,
    sync::atomic::AtomicBool,
};

use cbor_smol::{cbor_deserialize, cbor_serialize_bytes};
use littlefs2::{path, path::Path};
use serde::{de::DeserializeOwned, Serialize};
use strum_macros::FromRepr;
use trussed::{
    store::filestore::Filestore,
    try_syscall,
    types::{Location, Message, Vec},
    Client,
};

#[must_use]
/// Tell the admin APP whether a given configuration change requires factory-resetting another application
#[derive(Default, Debug, Clone)]
pub struct ResetClient {
    /// Boolean that must be set to true by the admin app to signal that the associated config value has been changed
    pub signal: Option<&'static AtomicBool>,
    /// Client ID to factory-reset if the associated configuration option is changed
    pub client_id: Option<&'static Path>,
}

const LOCATION: Location = Location::Internal;
const FILENAME: &Path = path!("config");

pub trait Config: Default + PartialEq + DeserializeOwned + Serialize {
    fn field(&mut self, key: &str) -> Option<ConfigValueMut<'_>>;

    /// Client ID to factory-reset if the associated configuration option is changed
    fn reset_client_id(&self, _key: &str) -> Option<&'static Path> {
        None
    }

    /// Boolean that must be set to true by the admin app to signal that the associated config value has been changed
    fn reset_signal(&self, _key: &str) -> Option<&'static AtomicBool> {
        None
    }
}

impl Config for () {
    fn field(&mut self, _key: &str) -> Option<ConfigValueMut<'_>> {
        None
    }
}

#[derive(Debug, Serialize)]
pub enum ConfigValueMut<'a> {
    Bool(&'a mut bool),
    U8(&'a mut u8),
}

impl<'a> ConfigValueMut<'a> {
    fn set(&mut self, value: &str) -> Result<(), ConfigError> {
        fn set_value<T: FromStr>(target: &mut T, s: &str) -> Result<(), ConfigError> {
            *target = s.parse().map_err(|_| ConfigError::InvalidValue)?;
            Ok(())
        }

        match self {
            Self::Bool(r) => set_value(*r, value),
            Self::U8(r) => set_value(*r, value),
        }
    }
}

impl<'a> Display for ConfigValueMut<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(value) => write!(f, "{}", value),
            Self::U8(value) => write!(f, "{}", value),
        }
    }
}

#[derive(Debug, FromRepr)]
#[repr(u8)]
pub enum ConfigError {
    ReadFailed = 1,
    WriteFailed = 2,
    DeserializationFailed = 3,
    SerializationFailed = 4,
    InvalidKey = 5,
    InvalidValue = 6,
    DataTooLong = 7,
    NotConfirmed = 8,
}

const _: () = assert!(
    ConfigError::from_repr(0).is_none(),
    "ConfigError may not have a variant with discriminant zero as zero indicates success.",
);

impl From<ConfigError> for u8 {
    fn from(error: ConfigError) -> u8 {
        error as _
    }
}

pub fn get<C: Config, const N: usize>(
    config: &mut C,
    key: &str,
    response: &mut Vec<u8, N>,
) -> Result<(), ConfigError> {
    let field = config.field(key).ok_or(ConfigError::InvalidKey)?;
    write!(response, "{}", field).map_err(|_| ConfigError::DataTooLong)
}

pub fn set<C: Config>(config: &mut C, key: &str, value: &str) -> Result<ResetClient, ConfigError> {
    config
        .field(key)
        .ok_or(ConfigError::InvalidKey)?
        .set(value)?;
    Ok(ResetClient {
        signal: config.reset_signal(key),
        client_id: config.reset_client_id(key),
    })
}

pub fn load<F: Filestore, C: Config>(store: &mut F) -> Result<C, ConfigError> {
    let Some(data) = load_if_exists(store, LOCATION, FILENAME)? else {
        return Ok(Default::default());
    };
    cbor_deserialize(&data).map_err(|_| ConfigError::DeserializationFailed)
}

pub fn save<T: Client, C: Config>(client: &mut T, config: &C) -> Result<(), ConfigError> {
    if config == &Default::default() {
        if exists(client, LOCATION, FILENAME)? {
            try_syscall!(client.remove_file(LOCATION, FILENAME.into()))
                .map_err(|_| ConfigError::WriteFailed)?;
        }
    } else {
        let data = cbor_serialize_bytes(config).map_err(|_| ConfigError::SerializationFailed)?;
        try_syscall!(client.write_file(LOCATION, FILENAME.into(), data, None))
            .map_err(|_| ConfigError::WriteFailed)?;
    }
    Ok(())
}

fn exists<T: Client>(client: &mut T, location: Location, path: &Path) -> Result<bool, ConfigError> {
    try_syscall!(client.entry_metadata(location, path.into()))
        .map(|r| r.metadata.is_some())
        .map_err(|_| ConfigError::ReadFailed)
}

fn load_if_exists<F: Filestore>(
    store: &mut F,
    location: Location,
    path: &Path,
) -> Result<Option<Message>, ConfigError> {
    store.read(path, location).map(Some).or_else(|_| {
        if store.exists(path, location) {
            Err(ConfigError::ReadFailed)
        } else {
            Ok(None)
        }
    })
}
