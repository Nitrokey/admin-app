use apdu_dispatch::iso7816::Status;
use apdu_dispatch::{app as apdu, command, response, Command as ApduCommand};
use core::{convert::TryInto, marker::PhantomData, time::Duration};
use ctaphid_dispatch::app::{self as hid, Command as HidCommand, Message};
use ctaphid_dispatch::command::VendorCommand;
#[cfg(feature = "se050")]
use embedded_hal::blocking::delay::DelayUs;
#[cfg(feature = "se050")]
use se05x::{se05x::Se05X, t1::I2CForT1};
use trussed::{interrupt::InterruptFlag, syscall, types::Vec, Client as TrussedClient};

pub const USER_PRESENCE_TIMEOUT_SECS: u32 = 15;

// New commands are only available over this vendor command (acting as a namespace for this
// application).  The actual application command is stored in the first byte of the packet data.
const ADMIN: VendorCommand = VendorCommand::H72;
const STATUS: u8 = 0x80;
const TEST_SE050: u8 = 0x81;

// For compatibility, old commands are also available directly as separate vendor commands.
const UPDATE: VendorCommand = VendorCommand::H51;
const REBOOT: VendorCommand = VendorCommand::H53;
const RNG: VendorCommand = VendorCommand::H60;
const VERSION: VendorCommand = VendorCommand::H61;
const UUID: VendorCommand = VendorCommand::H62;
const LOCKED: VendorCommand = VendorCommand::H63;

// We also handle the standard wink command.
const WINK: HidCommand = HidCommand::Wink; // 0x08

const RNG_DATA_LEN: usize = 57;

mod run_tests;
use run_tests::*;

/// Trait representing the possible ownership of the SE050 by the admin app.
///
/// Implemented by `()` and the `Se05X` struct
pub trait MaybeSe: RunTests {}

impl MaybeSe for () {}
#[cfg(feature = "se050")]
impl<Twi: I2CForT1, D: DelayUs<u32>> MaybeSe for Se05X<Twi, D> {}

#[derive(PartialEq, Debug)]
enum Command {
    Update,
    Reboot,
    Rng,
    Version,
    Uuid,
    Locked,
    Wink,
    Status,
    TestSe05X,
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(command: u8) -> Result<Self, Self::Error> {
        // First, check the old commands.
        if let Ok(command) = HidCommand::try_from(command) {
            if let Ok(command) = command.try_into() {
                return Ok(command);
            }
        }

        // Now check the new commands.
        match command {
            STATUS => Ok(Command::Status),
            TEST_SE050 => Ok(Command::TestSe05X),
            _ => Err(Error::UnsupportedCommand),
        }
    }
}

impl TryFrom<HidCommand> for Command {
    type Error = Error;

    fn try_from(command: HidCommand) -> Result<Self, Self::Error> {
        match command {
            WINK => Ok(Command::Wink),
            HidCommand::Vendor(command) => command.try_into(),
            _ => Err(Error::UnsupportedCommand),
        }
    }
}

impl TryFrom<VendorCommand> for Command {
    type Error = Error;

    fn try_from(command: VendorCommand) -> Result<Self, Self::Error> {
        match command {
            UPDATE => Ok(Command::Update),
            REBOOT => Ok(Command::Reboot),
            RNG => Ok(Command::Rng),
            VERSION => Ok(Command::Version),
            UUID => Ok(Command::Uuid),
            LOCKED => Ok(Command::Locked),
            _ => Err(Error::UnsupportedCommand),
        }
    }
}

enum Error {
    InvalidLength,
    NotAvailable,
    UnsupportedCommand,
}

impl From<Error> for hid::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidLength => Self::InvalidLength,
            // TODO: use more appropriate error code
            Error::NotAvailable => Self::InvalidLength,
            Error::UnsupportedCommand => Self::InvalidCommand,
        }
    }
}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidLength => Self::WrongLength,
            Error::NotAvailable => Self::ConditionsOfUseNotSatisfied,
            Error::UnsupportedCommand => Self::InstructionNotSupportedOrInvalid,
        }
    }
}

pub trait Reboot {
    /// Reboots the device.
    fn reboot() -> !;

    /// Reboots the device.
    ///
    /// Presuming the device has a separate mode of operation that
    /// allows updating its firmware (for instance, a bootloader),
    /// reboots the device into this mode.
    fn reboot_to_firmware_update() -> !;

    /// Reboots the device.
    ///
    /// Presuming the device has a separate destructive but more
    /// reliable way of rebooting into the firmware mode of operation,
    /// does so.
    fn reboot_to_firmware_update_destructive() -> !;

    /// Is device bootloader locked down?
    /// E.g., is secure boot enabled?
    fn locked() -> bool;
}

pub struct App<T, R, S, Se05X = ()>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
{
    trussed: T,
    uuid: [u8; 16],
    version: u32,
    full_version: &'static str,
    status: S,
    boot_interface: PhantomData<R>,
    se050: Se05X,
}

impl<T, R, S> App<T, R, S>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
{
    pub fn new(
        client: T,
        uuid: [u8; 16],
        version: u32,
        full_version: &'static str,
        status: S,
    ) -> Self {
        Self {
            trussed: client,
            uuid,
            version,
            full_version,
            status,
            boot_interface: PhantomData,
            se050: (),
        }
    }
}

#[cfg(feature = "se050")]
impl<T, R, S, Twi, D> App<T, R, S, Se05X<Twi, D>>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
    Twi: I2CForT1,
    D: DelayUs<u32>,
{
    pub fn with_se(
        client: T,
        uuid: [u8; 16],
        version: u32,
        full_version: &'static str,
        status: S,
        se050: Se05X<Twi, D>,
    ) -> Self {
        Self {
            trussed: client,
            uuid,
            version,
            full_version,
            status,
            boot_interface: PhantomData,
            se050,
        }
    }
}

impl<T, R, S, Se05X> App<T, R, S, Se05X>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
    Se05X: MaybeSe,
{
    fn user_present(&mut self) -> bool {
        let user_present = syscall!(self
            .trussed
            .confirm_user_present(USER_PRESENCE_TIMEOUT_SECS * 1000))
        .result;
        user_present.is_ok()
    }

    fn exec<const N: usize>(
        &mut self,
        command: Command,
        flag: Option<u8>,
        response: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
        debug_now!("Executing command: {command:?}");
        match command {
            Command::Reboot => R::reboot(),
            Command::Locked => {
                response.push(R::locked().into()).ok();
            }
            Command::Rng => {
                // Fill the HID packet (57 bytes)
                response
                    .extend_from_slice(&syscall!(self.trussed.random_bytes(RNG_DATA_LEN)).bytes)
                    .ok();
            }
            Command::Update => {
                if self.user_present() {
                    if flag == Some(0x01) {
                        R::reboot_to_firmware_update_destructive();
                    } else {
                        R::reboot_to_firmware_update();
                    }
                } else {
                    return Err(Error::NotAvailable);
                }
            }
            Command::Uuid => {
                // Get UUID
                response.extend_from_slice(&self.uuid).ok();
            }
            Command::Version => {
                // GET VERSION
                if flag == Some(0x01) {
                    response
                        .extend_from_slice(self.full_version.as_bytes())
                        .ok();
                } else {
                    response.extend_from_slice(&self.version.to_be_bytes()).ok();
                }
            }
            Command::Wink => {
                debug_now!("winking");
                syscall!(self.trussed.wink(Duration::from_secs(10)));
            }
            Command::Status => {
                response.extend_from_slice(self.status.as_ref()).ok();
            }
            Command::TestSe05X => {
                debug_now!("Running se050 tests");
                if let Err(_err) = self.se050.run_tests(response) {
                    debug_now!("se050 tests failed: {_err:?}");
                }
            }
        }
        Ok(())
    }
}

impl<T, R, S, Se> hid::App<'static> for App<T, R, S, Se>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
    Se: MaybeSe,
{
    fn commands(&self) -> &'static [HidCommand] {
        &[
            HidCommand::Wink,
            HidCommand::Vendor(ADMIN),
            HidCommand::Vendor(UPDATE),
            HidCommand::Vendor(REBOOT),
            HidCommand::Vendor(RNG),
            HidCommand::Vendor(VERSION),
            HidCommand::Vendor(UUID),
            HidCommand::Vendor(LOCKED),
        ]
    }

    fn call(
        &mut self,
        command: HidCommand,
        input_data: &Message,
        response: &mut Message,
    ) -> hid::AppResult {
        let (command, flag) = if command == HidCommand::Vendor(ADMIN) {
            // new mode: first input byte specifies the actual command
            let (command, input) = input_data.split_first().ok_or(Error::InvalidLength)?;
            let command = Command::try_from(*command)?;
            (command, input.first())
        } else {
            // old mode: directly use vendor commands + wink
            (Command::try_from(command)?, input_data.first())
        };
        self.exec(command, flag.copied(), response)
            .map_err(From::from)
    }

    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        self.trussed.interrupt()
    }
}

impl<T, R, S, Se> iso7816::App for App<T, R, S, Se>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
    Se: MaybeSe,
{
    // Solo management app
    fn aid(&self) -> iso7816::Aid {
        iso7816::Aid::new(&[0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01])
    }
}

impl<T, R, S, Se> apdu::App<{ command::SIZE }, { response::SIZE }> for App<T, R, S, Se>
where
    T: TrussedClient,
    R: Reboot,
    S: AsRef<[u8]>,
    Se: MaybeSe,
{
    fn select(&mut self, _apdu: &ApduCommand, _reply: &mut response::Data) -> apdu::Result {
        Ok(())
    }

    fn deselect(&mut self) {}

    fn call(
        &mut self,
        interface: apdu::Interface,
        apdu: &ApduCommand,
        reply: &mut response::Data,
    ) -> apdu::Result {
        let instruction: u8 = apdu.instruction().into();
        let command = Command::try_from(instruction)?;

        // Reboot may only be called over USB
        if command == Command::Reboot && interface != apdu::Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        self.exec(command, Some(apdu.p1), reply).map_err(From::from)
    }
}
