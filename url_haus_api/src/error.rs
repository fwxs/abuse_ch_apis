//! # Error Types
//!
//! This module defines error types used throughout the URL Haus API client.
//! All errors are variants of the [`Error`] enum and can be converted from various
//! standard library and external crate error types.

/// Represents all possible errors that can occur in the URL Haus API client.
///
/// This enum provides variants for different categories of errors encountered during
/// API operations, HTTP requests, and data parsing.
///
/// # Variants
///
/// * `Request` - An HTTP request error from the reqwest library (network, connection, timeout, etc.)
/// * `General` - A general-purpose error with a custom message
/// * `InvalidValue` - A validation error when a value doesn't meet requirements
/// * `CsvError` - A CSV parsing or deserialization error
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// HTTP request error from the reqwest library.
    ///
    /// Wraps a string representation of the underlying request error.
    /// Examples include network connectivity issues, timeouts, and HTTP status errors.
    Request(String),

    /// General-purpose error variant.
    ///
    /// Used for custom error messages and errors that don't fit other specific categories.
    /// Includes nom parsing errors from IDS rules, hosts files, and DNS RPZ parsing.
    General(String),

    /// Invalid value error variant.
    ///
    /// Indicates that a value provided doesn't meet validation constraints
    /// or is otherwise invalid for the operation being performed.
    InvalidValue(String),

    /// CSV parsing or deserialization error variant.
    ///
    /// Represents failures when deserializing CSV data into structs or
    /// when reading/writing CSV files.
    CsvError(String),
}

/// Converts a reqwest error into a [`Error::Request`].
///
/// This implementation allows reqwest errors to be automatically converted using the `?` operator
/// or `into()` method in functions that return `Result<T, Error>`.
impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Request(format!("Reqwest error: {}", err))
    }
}

/// Converts a static string reference into a [`Error::General`].
///
/// This implementation allows `&'static str` values to be used with the `?` operator
/// in functions that return `Result<T, Error>`.
impl From<&'static str> for Error {
    fn from(str_err: &'static str) -> Self {
        Error::General(String::from(str_err))
    }
}

/// Converts an owned String into a [`Error::General`].
///
/// This implementation allows dynamic strings to be converted into errors.
impl From<String> for Error {
    fn from(str_err: String) -> Self {
        Error::General(str_err)
    }
}

/// Converts a csv crate error into a [`Error::CsvError`].
///
/// This implementation allows CSV parsing errors to be automatically converted.
impl From<csv::Error> for Error {
    fn from(value: csv::Error) -> Self {
        Error::CsvError(value.to_string())
    }
}

/// Converts a nom parsing error (with owned string) into a [`Error::General`].
///
/// This implementation allows nom parser errors to be automatically converted.
/// Used when parsing IDS rules, hosts files, and DNS RPZ records.
impl From<nom::error::Error<String>> for Error {
    fn from(value: nom::error::Error<String>) -> Self {
        Error::General(format!("nom error: {:?}", value.code))
    }
}

/// Converts a nom parsing error (with string slice) into a [`Error::General`].
///
/// This implementation allows nom parser errors from borrowed string slices to be automatically converted.
/// Used when parsing IDS rules, hosts files, and DNS RPZ records.
impl From<nom::error::Error<&str>> for Error {
    fn from(value: nom::error::Error<&str>) -> Self {
        Error::General(format!("nom error: {:?}", value.code))
    }
}
