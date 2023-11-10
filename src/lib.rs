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
pub use config::{Config, ConfigError, ConfigValueMut};
use trussed_staging::manage::ManageClient;

#[cfg(not(feature = "se050"))]
pub trait Client: trussed::Client + ManageClient {}
#[cfg(not(feature = "se050"))]
impl<C: trussed::Client + ManageClient> Client for C {}

#[cfg(feature = "se050")]
pub trait Client: trussed::Client + trussed_se050_backend::manage::ManageClient {}
#[cfg(feature = "se050")]
impl<C: trussed::Client + trussed_se050_backend::manage::ManageClient> Client for C {}
