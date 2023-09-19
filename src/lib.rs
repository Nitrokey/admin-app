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
pub use admin::{App, Reboot};

#[cfg(not(feature = "se050"))]
pub trait Client: trussed::Client {}
#[cfg(not(feature = "se050"))]
impl<C: trussed::Client> Client for C {}

#[cfg(feature = "se050")]
pub trait Client: trussed::Client + trussed_se050_backend::manage::ManageClient {}
#[cfg(feature = "se050")]
impl<C: trussed::Client + trussed_se050_backend::manage::ManageClient> Client for C {}
