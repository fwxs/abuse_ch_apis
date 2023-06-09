use std::convert::Infallible;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    Request(String),
    General(String),
    QueryError(String),
    InvalidValue(String),
    InvalidJSON(String),
    Conversion(String)
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Request(format!("Reqwest error: {}", err))
    }
}

impl From<&'static str> for Error {
    fn from(str_err: &'static str) -> Self {
        Error::General(String::from(str_err))
    }
}

impl From<String> for Error {
    fn from(str_err: String) -> Self {
        Error::General(str_err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::InvalidJSON(value.to_string())
    }
}

impl From<Infallible> for Error {
    fn from(value: Infallible) -> Self {
        Self::Conversion(value.to_string())
    }
}
