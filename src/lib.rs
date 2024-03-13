//! # management-app
//!
//! A simple application that implements management operations,
//! such as firmware upgrade.
//!
//! It directly implements the APDU and CTAPHID dispatch App interfaces.
#![no_std]

#[macro_use]
extern crate delog;
generate_macros!();

mod admin;
mod config;

pub use admin::{App, Reboot};
pub use config::{Config, ConfigError, ConfigValueMut, ResetSignal, ResetSignalAllocation};
use trussed_manage::ManageClient;
#[cfg(feature = "se050")]
use trussed_se050_manage::Se050ManageClient;

#[cfg(not(feature = "se050"))]
pub trait Client: trussed::Client + ManageClient {}
#[cfg(not(feature = "se050"))]
impl<C: trussed::Client + ManageClient> Client for C {}

#[cfg(feature = "se050")]
pub trait Client:
    trussed::Client + Se050ManageClient + ManageClient
{
}
#[cfg(feature = "se050")]
impl<C: trussed::Client + Se050ManageClient + ManageClient> Client for C {}
