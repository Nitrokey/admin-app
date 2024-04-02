use core::{
    fmt::{self, Display, Formatter, Write as _},
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
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

#[derive(Debug)]
/// Structure meant to be stored in  a `static` to signal applications that they have been factory-resetted by the admin app
///
/// It is expected to have one such structure for each application supporting factory-reset by the admin-app
///
/// ```rust
///# use admin_app::{ResetSignalAllocation, ConfigValueMut};
///# use littlefs2::{path::Path, path};
/// #[derive(Default, PartialEq, serde::Deserialize, serde::Serialize)]
/// struct Config {
///    use_new_backend: bool,
///};
/// static OPCARD_RESET: ResetSignalAllocation = ResetSignalAllocation::new();
/// impl admin_app::Config for Config {
///     fn field(&mut self, key: &str) -> Option<ConfigValueMut<'_>> {
///         match key {
///             "opcard.use_new_backend" => Some(ConfigValueMut::Bool(&mut self.use_new_backend)),
///             _ => None,
///         }
///     }
///     /// Client ID to factory-reset if the associated configuration option is changed
///     fn reset_client_id(&self, key: &str) -> Option<(&'static Path, &'static ResetSignalAllocation)> {
///         match key {
///             "opcard" => Some((path!("opcard"), &OPCARD_RESET)),
///             "opcard.use_new_backend" =>Some((path!("opcard"), &OPCARD_RESET)),
///             _ => None,
///         }
///     }
/// }
/// ```
pub struct ResetSignalAllocation(AtomicU8);

impl ResetSignalAllocation {
    pub const fn new() -> Self {
        Self(AtomicU8::new(ResetSignal::None as u8))
    }

    pub fn load(&self) -> ResetSignal {
        let v = self.0.load(Ordering::Relaxed);
        ResetSignal::from_repr(v).expect("A reset signal value")
    }

    pub fn set_factory_reset(&self) -> bool {
        self.0
            .compare_exchange(
                ResetSignal::None as u8,
                ResetSignal::FactoryReset as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    pub fn set_config_changed(&self) {
        self.0
            .store(ResetSignal::ConfigChanged as u8, Ordering::Relaxed)
    }

    /// Factory reset can be acknowledged so that the application can restart working
    ///
    /// A configuration change cannot be acknowledged as it requires a power cycle to be taken into account.
    pub fn ack_factory_reset(&self) -> bool {
        self.0
            .compare_exchange(
                ResetSignal::FactoryReset as u8,
                ResetSignal::None as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}

#[derive(Debug, FromRepr, Default)]
#[repr(u8)]
pub enum ResetSignal {
    #[default]
    /// The App can continue operating
    None,
    /// The app has had it state factory reseted by the admin app
    ///
    /// It should delete any runtime state it is currently holding, then [`acknowledge`](ResetSignalAllocation::ack_factory_reset) the reset and continue working.
    FactoryReset,
    /// A configuration relevant to the application has been changed.
    ///
    /// The application must reject all incoming request and store no persistent state until a power cycle.
    ConfigChanged,
}

const LOCATION: Location = Location::Internal;
const FILENAME: &Path = path!("config");

pub trait Config: Default + PartialEq + DeserializeOwned + Serialize {
    fn field(&mut self, key: &str) -> Option<ConfigValueMut<'_>>;

    /// Client ID to factory-reset if the associated configuration option is changed
    ///
    /// # If the Request is for a `client_id`:
    ///
    /// - MUST return `Some` to indicate that the client can be factory reset by the admin app,
    /// - MUST return None otherwise.
    fn reset_client_id(
        &self,
        _key: &str,
    ) -> Option<(&'static Path, &'static ResetSignalAllocation)> {
        None
    }

    /// The migration version
    ///
    /// Return None if the configuration does not support storing the migration version
    fn migration_version(&self) -> Option<u32>;

    /// Set the migration version
    ///
    /// Return false if the configuration does not support storing the migration version
    fn set_migration_version(&mut self, _version: u32) -> bool;
}

impl Config for () {
    fn field(&mut self, _key: &str) -> Option<ConfigValueMut<'_>> {
        None
    }

    fn migration_version(&self) -> Option<u32> {
        None
    }

    fn set_migration_version(&mut self, _version: u32) -> bool {
        false
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

pub fn set<C: Config>(config: &mut C, key: &str, value: &str) -> Result<(), ConfigError> {
    config
        .field(key)
        .ok_or(ConfigError::InvalidKey)?
        .set(value)?;
    Ok(())
}

pub fn load<F: Filestore, C: Config>(store: &mut F) -> Result<C, ConfigError> {
    let Some(data) = load_if_exists(store, LOCATION, FILENAME)? else {
        return Ok(Default::default());
    };
    cbor_deserialize(&data).map_err(|_| ConfigError::DeserializationFailed)
}

pub fn save_filestore<F: Filestore, C: Config>(
    store: &mut F,
    config: &C,
) -> Result<(), ConfigError> {
    if config == &C::default() {
        if store.exists(FILENAME, LOCATION) {
            store
                .remove_file(FILENAME, LOCATION)
                .map_err(|_| ConfigError::WriteFailed)?;
        }
    } else {
        let data: Message =
            cbor_serialize_bytes(config).map_err(|_| ConfigError::SerializationFailed)?;
        store
            .write(FILENAME, LOCATION, &data)
            .map_err(|_| ConfigError::SerializationFailed)?;
    }
    Ok(())
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
