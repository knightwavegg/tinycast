//! Errors for this crate

use std::fmt;

/// An error thrown when resolving a function via signature failed
#[derive(Clone, Debug)]
pub enum FunctionSignatureError {
    MissingSignature,
    MissingToAddress,
}

impl fmt::Display for FunctionSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionSignatureError::MissingSignature => {
                writeln!(f, "Function signature must be set")
            }
            FunctionSignatureError::MissingToAddress => f.write_str("Target address must be set"),
        }
    }
}

impl std::error::Error for FunctionSignatureError {}
