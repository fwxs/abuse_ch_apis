//! # URL Haus Database Feed
//!
//! This module provides functions to fetch and parse URL Haus database dumps
//! in CSV format. It supports multiple database types including recent URLs
//! and actively hosted malicious URLs.

use crate::{error, WebFetch};
use serde::{de::DeserializeOwned, Deserialize};

/// URL for fetching recent URLs database dump (last 30 days).
const RECENT_URLS_DB_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";

/// URL for fetching active URLs database dump (currently online).
const ACTIVE_URLS_DB_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_online/";

/// Base URL for raw text-based URL feeds.
const RAW_URLS_BASE_URL: &str = "https://urlhaus.abuse.ch/downloads";

/// A recent malware URL record from the URL Haus database.
///
/// Represents a malicious URL discovered within the last 30 days,
/// including threat classification, reporting metadata, and status information.
#[derive(Debug, Deserialize)]
pub struct DBDumpRecentRecord {
    /// Unique identifier for this URL in the database.
    pub id: String,

    /// ISO 8601 date when this URL was added to the database.
    pub date_added: String,

    /// The actual malicious URL.
    pub url: String,

    /// Current status of the URL (e.g., "online", "offline").
    pub url_status: String,

    /// ISO 8601 timestamp of when this URL was last seen online.
    pub last_online: String,

    /// Classification of the threat type (e.g., "trojan", "malware_download", "phishing").
    pub threat: String,

    /// Comma-separated tags associated with this URL (e.g., "elf", "windows", "spyware").
    pub tags: String,

    /// Direct link to the URL Haus report for this URL.
    pub urlhaus_link: String,

    /// Name or identifier of the researcher who reported this URL.
    pub reporter: String,
}

/// An active malware URL record from the URL Haus database.
///
/// Represents a currently online malicious URL that is actively hosting malware
/// or conducting malicious activities.
#[derive(Debug, Deserialize)]
pub struct DBDumpActiveRecord {
    /// Unique identifier for this URL in the database.
    pub id: String,

    /// ISO 8601 date when this URL was added to the database.
    pub date_added: String,

    /// The actual malicious URL.
    pub url: String,

    /// Current status of the URL (typically "online" for active records).
    pub url_status: String,

    /// Classification of the threat type (e.g., "trojan", "malware_download", "phishing").
    pub threat: String,

    /// Comma-separated tags associated with this URL (e.g., "elf", "windows", "spyware").
    pub tags: String,

    /// Direct link to the URL Haus report for this URL.
    pub urlhaus_link: String,

    /// Name or identifier of the researcher who reported this URL.
    pub reporter: String,
}

/// Deserializes CSV data into a vector of records.
///
/// This helper function handles CSV deserialization with support for comment lines
/// and flexible header handling. Invalid records are silently skipped.
///
/// # Arguments
///
/// * `body` - The CSV content as a string
///
/// # Returns
///
/// A vector of successfully deserialized records of type `T`.
/// Invalid or malformed records are filtered out.
///
/// # Type Parameters
///
/// * `T` - The record type to deserialize into (must implement `Deserialize`)
fn deserialize_csv<T>(body: String) -> Result<Vec<T>, error::Error>
where
    T: Sized + DeserializeOwned,
{
    Ok(csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .has_headers(false)
        .from_reader(body.as_bytes())
        .deserialize::<T>()
        .filter(Result::is_ok)
        .map(|record| record.unwrap())
        .collect::<Vec<T>>())
}

/// Fetches and parses the recent URLs database dump.
///
/// Retrieves URLs discovered within the last 30 days from URL Haus
/// and returns them as structured records.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// A vector of [`DBDumpRecentRecord`] on success, or an [`error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
/// - The CSV data cannot be parsed
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::urls_db::fetch_recent_urls};
///
/// let client = HttpReqwest::default();
/// let recent_urls = fetch_recent_urls(&client)?;
/// for record in recent_urls {
///     println!("URL: {}, Threat: {}", record.url, record.threat);
/// }
/// ```
pub fn fetch_recent_urls(
    web_client: &impl WebFetch,
) -> Result<Vec<DBDumpRecentRecord>, error::Error> {
    deserialize_csv(web_client.fetch(RECENT_URLS_DB_URL)?)
}

/// Fetches and parses the active URLs database dump.
///
/// Retrieves currently online malicious URLs from URL Haus
/// and returns them as structured records.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// A vector of [`DBDumpActiveRecord`] on success, or an [`error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
/// - The CSV data cannot be parsed
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::urls_db::fetch_active_urls};
///
/// let client = HttpReqwest::default();
/// let active_urls = fetch_active_urls(&client)?;
/// for record in active_urls {
///     println!("Active URL: {}", record.url);
/// }
/// ```
pub fn fetch_active_urls(
    web_client: &impl WebFetch,
) -> Result<Vec<DBDumpActiveRecord>, error::Error> {
    deserialize_csv(web_client.fetch(ACTIVE_URLS_DB_URL)?)
}

/// Database type selector for raw text URL feeds.
///
/// Specifies which type of URL database to fetch in plain text format.
pub enum DBType {
    /// Complete database of all known malicious URLs.
    FULL,

    /// Database of recently added URLs (last 30 days).
    RECENT,

    /// Database of currently active/online URLs.
    ACTIVE,
}

impl DBType {
    /// Returns the API endpoint suffix for this database type.
    ///
    /// # Returns
    ///
    /// A string slice representing the endpoint path component.
    fn url<'a>(self) -> &'a str {
        match self {
            Self::FULL => "text",
            Self::RECENT => "text_recent",
            Self::ACTIVE => "text_online",
        }
    }
}

/// Fetches a raw text-based URL feed from URL Haus.
///
/// Retrieves malicious URLs in plain text format (one URL per line)
/// from the specified database type.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
/// * `db_type` - The type of database to fetch
///
/// # Returns
///
/// A vector of URLs as strings on success, or an [`error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
/// - The feed format is invalid
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::urls_db::{fetch_raw_urls_txt_db, DBType}};
///
/// let client = HttpReqwest::default();
/// let urls = fetch_raw_urls_txt_db(&client, DBType::RECENT)?;
/// println!("Fetched {} URLs", urls.len());
/// ```
pub fn fetch_raw_urls_txt_db(
    web_client: &impl WebFetch,
    db_type: DBType,
) -> Result<Vec<String>, error::Error> {
    let url = format!("{}/{}/", RAW_URLS_BASE_URL, db_type.url());

    Ok(web_client
        .fetch(url.as_str())?
        .lines()
        .map(String::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const NOT_FOUND_ERROR: &'static str = "
        <!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
        <html><head>
        <title>404 Not Found</title>
        </head><body>
        <h1>Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <hr>
        <address>Apache Server at urlhaus.abuse.ch Port 443</address>
        </body></html>
    ";

    #[test]
    fn test_retrieve_url_haus_recent_urls_database_dump() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/url_haus_30_days.csv").to_string());
        let db_dump: Vec<DBDumpRecentRecord> = fetch_recent_urls(&fake_reqwest)?;

        assert!(!db_dump.is_empty(), "Retrieved DB cannot be empty");

        return Ok(());
    }

    #[test]
    fn test_retrieve_url_haus_active_urls_database_dump() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("test_files/url_haus_30_days_active.csv").to_string(),
        );
        let db_dump: Vec<DBDumpActiveRecord> = fetch_active_urls(&fake_reqwest)?;

        assert!(!db_dump.is_empty(), "Retrieved DB cannot be empty");

        return Ok(());
    }

    #[test]
    fn test_return_error_on_database_not_found() {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_error_response(error::Error::Request(NOT_FOUND_ERROR.to_string()));
        let db_dump_err = fetch_recent_urls(&fake_reqwest).unwrap_err();

        assert_eq!(
            db_dump_err,
            error::Error::Request(NOT_FOUND_ERROR.to_string())
        );
    }

    #[test]
    fn test_return_empty_vector_on_invalid_csv() -> Result<(), error::Error> {
        let fake_reqwest =
            FakeHttpReqwest::default().set_success_response(NOT_FOUND_ERROR.to_string());
        let res = fetch_active_urls(&fake_reqwest)?;

        assert!(res.is_empty(), "CSV is not empty");

        return Ok(());
    }

    #[test]
    fn test_fetch_raw_urls_txt_db() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/raw_urls.txt").to_string());
        let db_dump: Vec<String> = fetch_raw_urls_txt_db(&fake_reqwest, DBType::RECENT)?;

        assert_eq!(db_dump.len(), 8);

        Ok(())
    }
}
