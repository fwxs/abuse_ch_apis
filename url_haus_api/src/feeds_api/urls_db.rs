use crate::{error, WebFetch};
use serde::{de::DeserializeOwned, Deserialize};

const RECENT_URLS_DB_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const ACTIVE_URLS_DB_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_online/";
const RAW_URLS_BASE_URL: &str = "https://urlhaus.abuse.ch/downloads";

#[derive(Debug, Deserialize)]
pub struct DBDumpRecentRecord {
    pub id: String,
    pub date_added: String,
    pub url: String,
    pub url_status: String,
    pub last_online: String,
    pub threat: String,
    pub tags: String,
    pub urlhaus_link: String,
    pub reporter: String,
}

#[derive(Debug, Deserialize)]
pub struct DBDumpActiveRecord {
    pub id: String,
    pub date_added: String,
    pub url: String,
    pub url_status: String,
    pub threat: String,
    pub tags: String,
    pub urlhaus_link: String,
    pub reporter: String,
}

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

pub fn fetch_recent_urls(
    web_client: &impl WebFetch,
) -> Result<Vec<DBDumpRecentRecord>, error::Error> {
    deserialize_csv(web_client.fetch(RECENT_URLS_DB_URL)?)
}

pub fn fetch_active_urls(
    web_client: &impl WebFetch,
) -> Result<Vec<DBDumpActiveRecord>, error::Error> {
    deserialize_csv(web_client.fetch(ACTIVE_URLS_DB_URL)?)
}

pub enum DBType {
    FULL,
    RECENT,
    ACTIVE,
}

impl DBType {
    fn url<'a>(self) -> &'a str {
        match self {
            Self::FULL => "text",
            Self::RECENT => "text_recent",
            Self::ACTIVE => "text_online",
        }
    }
}

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
