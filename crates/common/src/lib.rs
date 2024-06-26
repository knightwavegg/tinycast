//! Common utilities for building and using foundry's tools.

#![warn(missing_docs, unused_crate_dependencies)]

extern crate self as foundry_common;

#[macro_use]
extern crate tracing;

pub mod abi;
pub mod calc;
pub mod constants;
pub mod contracts;
pub mod errors;
pub mod fmt;
pub mod fs;
pub mod glob;
pub mod retry;
pub mod selectors;
pub mod serde_helpers;
pub mod shell;
pub mod term;
pub mod traits;
pub mod types;

pub use constants::*;
pub use contracts::*;
pub use traits::*;
