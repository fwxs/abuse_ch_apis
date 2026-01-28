//! # Query Operations and Response Types
//!
//! This module provides the core functionality for querying the Threat Fox API.
//! It includes query operation types, response structures, and functions to execute queries.
//!
//! ## Query Operations
//!
//! The [`IoCQueryType`] enum represents different types of queries that can be performed:
//! - Recent IoCs retrieval (1-7 days lookback)
//! - Single IoC lookup by ID
//! - IoC searches by indicator value
//! - Hash-based searches
//! - Tag and malware family information queries
//!
//! ## Response Structures
//!
//! The main response type is [`IocInformation`], which contains comprehensive details about
//! an indicator of compromise including threat types, malware families, and related samples.
//!
//! Additional data retrieval functions return [`ThreatType`], [`Tag`], and [`MalwareFamily`] information.

extern crate serde_json;

use serde::{Deserialize, Serialize};

use crate::WebFetch;

/// A type alias for query results.
///
/// All query operations return this type, where `T` is the result data type
/// and [`crate::error::Error`] represents potential failures.
pub type QueryResult<T> = Result<T, crate::error::Error>;

/// The base URL for the Threat Fox API v1 endpoint.
const THREAT_FOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

/// Generic API response wrapper for Threat Fox queries.
///
/// Wraps the actual query results with status information. If the query succeeded,
/// the `data` field contains the results; otherwise, it contains an error description.
#[derive(Debug, Deserialize)]
pub struct QueryResponse {
    /// Status of the query execution (e.g., "ok", "unknown_operation").
    #[serde(rename = "query_status")]
    query_status: String,

    /// Response data payload (varies by query type).
    #[serde(rename = "data")]
    data: serde_json::Value,
}

/// Comprehensive information about an indicator of compromise (IoC).
///
/// This struct represents a detailed IoC record from Threat Fox, containing
/// information about threat types, associated malware, confidence levels, and related samples.
#[derive(Debug, Serialize, Deserialize)]
pub struct IocInformation {
    /// Unique identifier for this IoC in the database.
    #[serde(rename = "id")]
    pub id: Option<String>,

    /// The actual indicator of compromise (IP, domain, URL, file hash, etc.).
    #[serde(rename = "ioc")]
    pub ioc: Option<String>,

    /// Threat type classification code (e.g., "trojan", "ransomware", "botnet").
    #[serde(rename = "threat_type")]
    pub threat_type: Option<String>,

    /// Human-readable description of the threat type.
    #[serde(rename = "threat_type_desc")]
    pub threat_type_desc: Option<String>,

    /// IoC type classification (e.g., "domain", "url", "ip:port", "md5_hash", "sha256_hash").
    #[serde(rename = "ioc_type")]
    pub ioc_type: Option<String>,

    /// Human-readable description of the IoC type.
    #[serde(rename = "ioc_type_desc")]
    pub ioc_type_desc: Option<String>,

    /// Malware family identifier (cryptographic hash-based identifier).
    #[serde(rename = "malware")]
    pub malware: Option<String>,

    /// Human-readable malware family name (e.g., "Emotet", "Trickbot").
    #[serde(rename = "malware_printable")]
    pub malware_printable: Option<String>,

    /// Alternative names or aliases for the malware family.
    #[serde(rename = "malware_alias")]
    pub malware_alias: Option<serde_json::Value>,

    /// Link to Malpedia information about the malware family.
    #[serde(rename = "malware_malpedia")]
    pub malware_malpedia: Option<String>,

    /// Confidence level of the threat classification (typically 0-100).
    #[serde(rename = "confidence_level")]
    pub confidence_level: i64,

    /// ISO 8601 timestamp of when this IoC was first seen.
    #[serde(rename = "first_seen")]
    pub first_seen: Option<String>,

    /// ISO 8601 timestamp of when this IoC was last seen (or null if still active).
    #[serde(rename = "last_seen")]
    pub last_seen: Option<serde_json::Value>,

    /// URL reference or source information for this IoC report.
    #[serde(rename = "reference")]
    pub reference: Option<String>,

    /// Name or identifier of the reporter who submitted this IoC.
    #[serde(rename = "reporter")]
    pub reporter: Option<String>,

    /// Additional user-provided comment or annotation about this IoC.
    #[serde(rename = "comment")]
    pub comment: Option<String>,

    /// List of tags associated with this IoC (e.g., "phishing", "c2", "spam").
    #[serde(rename = "tags")]
    pub tags: Option<Vec<String>>,

    /// Credits information for security researchers who contributed to this report.
    #[serde(rename = "credits")]
    pub credits: Option<Vec<Credit>>,

    /// Malware samples (hashes) associated with this IoC.
    #[serde(rename = "malware_samples")]
    pub malware_samples: Option<Vec<MalwareSample>>,
}

/// Credit attribution for security researchers.
///
/// Represents attribution to individuals or organizations who contributed to threat intelligence.
#[derive(Debug, Serialize, Deserialize)]
pub struct Credit {
    /// Name or identifier of the researcher or organization receiving credit.
    #[serde(rename = "credits_from")]
    pub credits_from: Option<String>,

    /// Credit points or amount awarded.
    #[serde(rename = "credits_amount")]
    pub credits_amount: i64,
}

/// Information about a malware sample associated with an IoC.
///
/// Represents a malware binary or executable linked to a threat indicator.
#[derive(Debug, Serialize, Deserialize)]
pub struct MalwareSample {
    /// ISO 8601 timestamp of when this sample was detected.
    #[serde(rename = "time_stamp")]
    pub time_stamp: Option<String>,

    /// MD5 hash of the malware sample.
    #[serde(rename = "md5_hash")]
    pub md5_hash: Option<String>,

    /// SHA256 hash of the malware sample.
    #[serde(rename = "sha256_hash")]
    pub sha256_hash: Option<String>,

    /// URL link to this sample in the Malware Bazaar database.
    #[serde(rename = "malware_bazaar")]
    pub malware_bazaar: Option<String>,
}

/// Result limit for queries that return multiple matches.
///
/// Used to control the maximum number of results returned by queries like
/// tag searches and malware info queries. The maximum allowed limit is 1000.
pub enum QueryLimit {
    /// Use the default limit of 100 results.
    Default,

    /// Specify a custom limit (must be less than or equal to 1000).
    Limit(i32),
}

/// Conversion of [`QueryLimit`] to an i32 limit value.
///
/// Validates that custom limits do not exceed the maximum of 1000 and
/// returns the default limit of 100 for [`QueryLimit::Default`].
impl TryInto<i32> for QueryLimit {
    type Error = crate::error::Error;

    fn try_into(self) -> Result<i32, Self::Error> {
        match self {
            Self::Limit(limit) if limit > 1000 => Err(crate::error::Error::InvalidValue(format!(
                "Limit should be less than 1000. Specified limit {}",
                limit
            ))),
            Self::Limit(limit) => Ok(limit),
            Self::Default => Ok(100),
        }
    }
}

/// Internal structure for building IoC query parameters.
///
/// Used to construct the HashMap of query parameters that will be sent to the API.
/// This is an internal type not exposed in the public API.
pub struct IocQueryOperation<'a> {
    /// The API operation/query type (e.g., "get_iocs", "ioc", "search_ioc").
    operation: &'a str,

    /// The parameter name for the query value (e.g., "days", "id", "search_term").
    query_key: Option<&'a str>,

    /// The actual value to query for (e.g., days, IoC ID, search term).
    query_value: Option<String>,

    /// Optional result limit for multi-result queries.
    limit: Option<QueryLimit>,
}

/// Conversion of [`IocQueryOperation`] into a HashMap for API requests.
///
/// Builds the final query parameter map including the operation, optional key-value pair,
/// and optional limit, handling validation of the limit value.
impl<'a> TryInto<std::collections::HashMap<&'a str, String>> for IocQueryOperation<'a> {
    type Error = crate::error::Error;

    fn try_into(self) -> Result<std::collections::HashMap<&'a str, String>, Self::Error> {
        let mut query_json =
            std::collections::HashMap::from([("query", self.operation.to_string())]);

        if let (Some(query_key), Some(query_value)) = (self.query_key, self.query_value) {
            query_json.insert(query_key, query_value);
        }

        if let Some(limit) = self.limit {
            query_json.insert(
                "limit",
                <QueryLimit as TryInto<i32>>::try_into(limit)?.to_string(),
            );
        }

        Ok(query_json)
    }
}

/// Query operations available in the Threat Fox API.
///
/// Represents the different types of queries that can be performed, including
/// recent IoC retrieval, individual IoC lookups, searches, and metadata queries.
pub enum IoCQueryType {
    /// Retrieve recent IoCs added within the specified number of days (1-7).
    GetRecentIoCs(i32),

    /// Query a specific IoC by its unique ID.
    IoC(i32),

    /// Search for IoCs matching a search term (domain, IP, URL, etc.).
    SearchIoC(String),

    /// Search for IoCs by file hash (MD5, SHA256, etc.).
    SearchHash(String),

    /// Query samples by a specific tag with optional result limit.
    TagInfo(String, QueryLimit),

    /// Query samples by malware family with optional result limit.
    MalwareInfo(String, QueryLimit),
}

/// Conversion of [`IoCQueryType`] into a HashMap for API requests.
///
/// Transforms query operation variants into the appropriate API parameters,
/// including operation names, parameter keys/values, and optional limits.
/// Validates that day values are within the valid range (1-7).
impl TryInto<std::collections::HashMap<&str, String>> for IoCQueryType {
    type Error = crate::error::Error;

    fn try_into(self) -> Result<std::collections::HashMap<&'static str, String>, Self::Error> {
        let query_op = match self {
            IoCQueryType::GetRecentIoCs(days) if days < 1 || days > 7 => {
                return Err(crate::error::Error::InvalidValue(format!(
                    "Invalid {} days. Days should be between 1 and 7",
                    days
                )))
            }
            IoCQueryType::GetRecentIoCs(days) => IocQueryOperation {
                operation: "get_iocs",
                query_key: Some("days"),
                query_value: Some(days.to_string()),
                limit: None,
            },
            IoCQueryType::IoC(ioc_id) => IocQueryOperation {
                operation: "ioc",
                query_key: Some("id"),
                query_value: Some(ioc_id.to_string()),
                limit: None,
            },
            IoCQueryType::SearchIoC(ioc) => IocQueryOperation {
                operation: "search_ioc",
                query_key: Some("search_term"),
                query_value: Some(ioc),
                limit: None,
            },
            IoCQueryType::SearchHash(ioc_hash) => IocQueryOperation {
                operation: "search_hash",
                query_key: Some("hash"),
                query_value: Some(ioc_hash),
                limit: None,
            },
            IoCQueryType::TagInfo(ioc_tag, limit) => IocQueryOperation {
                operation: "taginfo",
                query_key: Some("tag"),
                query_value: Some(ioc_tag),
                limit: Some(limit),
            },
            IoCQueryType::MalwareInfo(malware_family, limit) => IocQueryOperation {
                operation: "malwareinfo",
                query_key: Some("malware"),
                query_value: Some(malware_family),
                limit: Some(limit),
            },
        };

        query_op.try_into()
    }
}

/// Queries the Threat Fox API for indicators of compromise.
///
/// Executes a query operation and returns a list of matching IoCs with comprehensive
/// information including threat types, malware families, confidence levels, and related samples.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
/// * `query_type` - The specific query operation to perform
///
/// # Returns
///
/// Returns a vector of [`IocInformation`] structs on success, or an
/// [`crate::error::Error`] on failure (network error, invalid query, etc.).
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The API returns an error status
/// - The response cannot be parsed as JSON
/// - The query parameters are invalid (e.g., days outside 1-7 range)
///
/// # Example
///
/// ```ignore
/// use threat_fox_api::{HttpReqwest, queries::{IoCQueryType, query_iocs_info}};
///
/// let client = HttpReqwest::default();
/// let query = IoCQueryType::GetRecentIoCs(2);
/// let results = query_iocs_info(&client, query)?;
/// ```
pub fn query_iocs_info(
    web_client: &impl WebFetch,
    query_type: IoCQueryType,
) -> QueryResult<Vec<IocInformation>> {
    let response = web_client.fetch(THREAT_FOX_URL, query_type.try_into()?)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        Err(crate::error::Error::QueryError(response.data.to_string()))
    } else {
        Ok(serde_json::from_value(response.data)?)
    }
}

/// Information about a threat type classification in Threat Fox.
///
/// Describes a threat type used to classify IoCs, including its code,
/// human-readable name, and description.
#[derive(Serialize, Deserialize, Debug)]
pub struct ThreatType {
    /// The IoC type code (e.g., "domain", "url", "ip:port").
    pub ioc_type: String,

    /// The threat type name (e.g., "trojan", "ransomware", "botnet").
    pub threat_type_name: String,

    /// Human-readable description of the threat type.
    pub description: String,
}

/// Retrieves all available threat type classifications from Threat Fox.
///
/// Returns a list of all threat types used to classify indicators of compromise,
/// including their codes, names, and descriptions.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// Returns a vector of [`ThreatType`] structs on success, or an [`crate::error::Error`]
/// on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The API returns an error status
/// - The response cannot be parsed as JSON
///
/// # Example
///
/// ```ignore
/// use threat_fox_api::{HttpReqwest, queries::retrieve_threat_types};
///
/// let client = HttpReqwest::default();
/// let threat_types = retrieve_threat_types(&client)?;
/// for threat_type in threat_types {
///     println!("Threat Type: {} - {}", threat_type.threat_type_name, threat_type.description);
/// }
/// ```
pub fn retrieve_threat_types(web_client: &impl WebFetch) -> QueryResult<Vec<ThreatType>> {
    let query_param = std::collections::HashMap::from([("query", String::from("types"))]);
    let response = web_client.fetch(THREAT_FOX_URL, query_param)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        return Err(crate::error::Error::QueryError(response.data.to_string()));
    }

    Ok(serde_json::from_value::<
        std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    >(response.data)?
    .into_iter()
    .map(|(_, value)| ThreatType {
        ioc_type: value
            .get("ioc_type")
            .map_or_else(String::default, String::to_string),
        threat_type_name: value
            .get("fk_threat_type")
            .map_or_else(String::default, String::to_string),
        description: value
            .get("description")
            .map_or_else(String::default, String::to_string),
    })
    .collect::<Vec<ThreatType>>())
}

/// Information about a tag used to classify IoCs in Threat Fox.
///
/// Tags are used to categorize and organize indicators of compromise
/// for better filtering and analysis.
#[derive(Serialize, Deserialize, Debug)]
pub struct Tag {
    /// The tag name (e.g., "phishing", "c2", "botnet").
    pub name: String,

    /// ISO 8601 timestamp of when this tag was first seen.
    pub first_seen: String,

    /// ISO 8601 timestamp of when this tag was last seen.
    pub last_seen: String,

    /// Hex color code for visual representation of the tag.
    pub color: String,
}

/// Retrieves all available tags used to classify IoCs in Threat Fox.
///
/// Returns a list of all tags available for categorizing indicators of compromise,
/// including their names, temporal information, and visual colors.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// Returns a vector of [`Tag`] structs on success, or an [`crate::error::Error`]
/// on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The API returns an error status
/// - The response cannot be parsed as JSON
///
/// # Example
///
/// ```ignore
/// use threat_fox_api::{HttpReqwest, queries::retrieve_tags};
///
/// let client = HttpReqwest::default();
/// let tags = retrieve_tags(&client)?;
/// for tag in tags {
///     println!("Tag: {} (Color: {})", tag.name, tag.color);
/// }
/// ```
pub fn retrieve_tags(web_client: &impl WebFetch) -> QueryResult<Vec<Tag>> {
    let query_param = std::collections::HashMap::from([("query", String::from("tag_list"))]);
    let response = web_client.fetch(THREAT_FOX_URL, query_param)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        return Err(crate::error::Error::QueryError(response.data.to_string()));
    }

    Ok(serde_json::from_value::<
        std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    >(response.data)?
    .into_iter()
    .map(|(key, value)| Tag {
        name: key,
        last_seen: value
            .get("last_seen")
            .map_or_else(String::default, String::to_string),
        first_seen: value
            .get("first_seen")
            .map_or_else(String::default, String::to_string),
        color: value
            .get("color")
            .map_or_else(String::default, String::to_string),
    })
    .collect::<Vec<Tag>>())
}

/// Information about a malware family tracked in Threat Fox.
///
/// Represents a malware family with its identifier, human-readable name,
/// and known aliases.
#[derive(Default, Debug)]
pub struct MalwareFamily {
    /// The malware family identifier (cryptographic hash-based).
    pub name: String,

    /// Human-readable malware family name (e.g., "Emotet", "Trickbot").
    pub malware_printable: String,

    /// Known aliases or alternative names for this malware family.
    pub malware_alias: Option<String>,
}

/// Retrieves all malware families tracked in Threat Fox.
///
/// Returns a list of all malware families with their identifiers, human-readable names,
/// and known aliases.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// Returns a vector of [`MalwareFamily`] structs on success, or an [`crate::error::Error`]
/// on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The API returns an error status
/// - The response cannot be parsed as JSON
///
/// # Example
///
/// ```ignore
/// use threat_fox_api::{HttpReqwest, queries::retrieve_malware_families};
///
/// let client = HttpReqwest::default();
/// let families = retrieve_malware_families(&client)?;
/// for family in families {
///     println!("Family: {} - {}", family.malware_printable, family.name);
/// }
/// ```
pub fn retrieve_malware_families(web_client: &impl WebFetch) -> QueryResult<Vec<MalwareFamily>> {
    let query_param = std::collections::HashMap::from([("query", String::from("tag_list"))]);
    let response = web_client.fetch(THREAT_FOX_URL, query_param)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        return Err(crate::error::Error::QueryError(response.data.to_string()));
    }

    Ok(serde_json::from_value::<
        std::collections::HashMap<String, std::collections::HashMap<String, Option<String>>>,
    >(response.data)?
    .into_iter()
    .map(|(key, value)| MalwareFamily {
        name: key,
        malware_printable: value
            .get("malware_printable")
            .map_or(String::new(), |malware_printable| {
                malware_printable.clone().unwrap()
            }),
        malware_alias: value
            .get("malware_alias")
            .map_or(None, |malware_alias| malware_alias.clone()),
    })
    .collect::<Vec<MalwareFamily>>())
}

#[cfg(test)]
mod tests {
    use crate::fakers::FakeHttpReqwest;
    use crate::queries::{
        query_iocs_info, retrieve_malware_families, retrieve_tags, retrieve_threat_types,
    };

    use super::IoCQueryType;

    const QUERY_ERROR: &str = "{
        \"query_status\": \"unknown_operation\",
        \"data\": \"The operation is unknown. Please check the query parameter\"
    }";

    #[test]
    fn test_retrieve_iocs() {
        let web_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/recent_iocs_resp.json").to_string());
        let result = query_iocs_info(&web_client, IoCQueryType::GetRecentIoCs(2));

        assert!(
            !result.unwrap().is_empty(),
            "Malware information cannot be empty"
        );
    }

    #[test]
    fn test_return_query_error() {
        let web_client = FakeHttpReqwest::default().set_success_response(QUERY_ERROR.to_string());
        let result = query_iocs_info(&web_client, IoCQueryType::GetRecentIoCs(2)).unwrap_err();

        assert!(
            matches!(result, crate::error::Error::QueryError(_)),
            "Error is not QueryError"
        );
    }

    #[test]
    fn test_retrieve_threat_types() {
        let web_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/threat_types.json").to_string());
        let result = retrieve_threat_types(&web_client);

        assert!(!result.unwrap().is_empty(), "Threat types cannot be empty");
    }

    #[test]
    fn test_retrieve_tag_list() {
        let web_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/tag_list.json").to_string());
        let result = retrieve_tags(&web_client);

        assert!(!result.unwrap().is_empty(), "Threat tags cannot be empty");
    }

    #[test]
    fn test_retrieve_malware_families() {
        let web_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/malware_families.json").to_string());
        let result = retrieve_malware_families(&web_client);

        assert!(
            !result.unwrap().is_empty(),
            "Malware families response cannot be empty"
        );
    }
}
