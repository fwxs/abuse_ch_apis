#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    Request(String),
    General(String),
    InvalidValue(String),
    CsvError(String),
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

impl From<csv::Error> for Error {
    fn from(value: csv::Error) -> Self {
        Error::CsvError(value.to_string())
    }
}

impl From<nom::error::Error<String>> for Error {
    fn from(value: nom::error::Error<String>) -> Self {
        Error::General(format!("nom error: {:?}", value.code))
    }
}

impl From<nom::error::Error<&str>> for Error {
    fn from(value: nom::error::Error<&str>) -> Self {
        Error::General(format!("nom error: {:?}", value.code))
    }
}
