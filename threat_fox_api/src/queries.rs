extern crate serde_json;

use serde::{Deserialize, Serialize};

use crate::WebFetch;

pub type QueryResult<T> = Result<T, crate::error::Error>;
const THREAT_FOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

#[derive(Debug, Deserialize)]
pub struct QueryResponse {
    #[serde(rename = "query_status")]
    query_status: String,

    #[serde(rename = "data")]
    data: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IocInformation {
    #[serde(rename = "id")]
    id: Option<String>,

    #[serde(rename = "ioc")]
    ioc: Option<String>,

    #[serde(rename = "threat_type")]
    threat_type: Option<String>,

    #[serde(rename = "threat_type_desc")]
    threat_type_desc: Option<String>,

    #[serde(rename = "ioc_type")]
    ioc_type: Option<String>,

    #[serde(rename = "ioc_type_desc")]
    ioc_type_desc: Option<String>,

    #[serde(rename = "malware")]
    malware: Option<String>,

    #[serde(rename = "malware_printable")]
    malware_printable: Option<String>,

    #[serde(rename = "malware_alias")]
    malware_alias: Option<serde_json::Value>,

    #[serde(rename = "malware_malpedia")]
    malware_malpedia: Option<String>,

    #[serde(rename = "confidence_level")]
    confidence_level: i64,

    #[serde(rename = "first_seen")]
    first_seen: Option<String>,

    #[serde(rename = "last_seen")]
    last_seen: Option<serde_json::Value>,

    #[serde(rename = "reference")]
    reference: Option<String>,

    #[serde(rename = "reporter")]
    reporter: Option<String>,

    #[serde(rename = "comment")]
    comment: Option<String>,

    #[serde(rename = "tags")]
    tags: Option<Vec<String>>,

    #[serde(rename = "credits")]
    credits: Option<Vec<Credit>>,

    #[serde(rename = "malware_samples")]
    malware_samples: Option<Vec<MalwareSample>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credit {
    #[serde(rename = "credits_from")]
    credits_from: Option<String>,

    #[serde(rename = "credits_amount")]
    credits_amount: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MalwareSample {
    #[serde(rename = "time_stamp")]
    time_stamp: Option<String>,

    #[serde(rename = "md5_hash")]
    md5_hash: Option<String>,

    #[serde(rename = "sha256_hash")]
    sha256_hash: Option<String>,

    #[serde(rename = "malware_bazaar")]
    malware_bazaar: Option<String>,
}

pub enum QueryLimit {
    Default,
    Limit(i32),
}

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

pub struct IocQueryOperation<'a> {
    operation: &'a str,
    query_key: Option<&'a str>,
    query_value: Option<String>,
    limit: Option<QueryLimit>,
}

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

pub enum IoCQueryType {
    GetRecentIoCs(i32),
    IoC(i32),
    SearchIoC(String),
    SearchHash(String),
    TagInfo(String, QueryLimit),
    MalwareInfo(String, QueryLimit),
}

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

#[derive(Serialize, Deserialize, Debug)]
pub struct ThreatType {
    pub ioc_type: String,
    pub threat_type_name: String,
    pub description: String
}

pub fn retrieve_threat_types(web_client: &impl WebFetch) -> QueryResult<Vec<ThreatType>> {
    let query_param = std::collections::HashMap::from(
        [
            ("query", String::from("types"))
        ]
    );
    let response = web_client.fetch(THREAT_FOX_URL, query_param)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        return Err(crate::error::Error::QueryError(response.data.to_string()))
    }

    Ok(
        serde_json::from_value::<std::collections::HashMap<String, std::collections::HashMap<String, String>>>(
            response.data
        )?
        .into_iter()
        .map(
            |(_, value)| ThreatType {
                ioc_type: value.get("ioc_type").map_or_else(String::default, String::to_string),
                threat_type_name: value.get("fk_threat_type").map_or_else(String::default, String::to_string),
                description: value.get("description").map_or_else(String::default, String::to_string)
            }
        )
        .collect::<Vec<ThreatType>>()
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tag {
    pub name: String,
    pub first_seen: String,
    pub last_seen: String,
    pub color: String
}

pub fn retrieve_tags(web_client: &impl WebFetch) -> QueryResult<Vec<Tag>> {
    let query_param = std::collections::HashMap::from(
        [
            ("query", String::from("tag_list"))
        ]
    );
    let response = web_client.fetch(THREAT_FOX_URL, query_param)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        return Err(crate::error::Error::QueryError(response.data.to_string()))
    }

    Ok(
        serde_json::from_value::<std::collections::HashMap<String, std::collections::HashMap<String, String>>>(
            response.data
        )?
        .into_iter()
        .map(
            |(key, value)| Tag {
                name: key,
                last_seen: value.get("last_seen").map_or_else(String::default, String::to_string),
                first_seen: value.get("first_seen").map_or_else(String::default, String::to_string),
                color: value.get("color").map_or_else(String::default, String::to_string)
            }
        )
        .collect::<Vec<Tag>>()
    )
}

#[derive(Default, Debug)]
pub struct MalwareFamily {
    pub name: String,
    pub malware_printable: String,
    pub malware_alias: Option<String>
}

pub fn retrieve_malware_families(web_client: &impl WebFetch) -> QueryResult<Vec<MalwareFamily>> {
    let query_param = std::collections::HashMap::from(
        [
            ("query", String::from("tag_list"))
        ]
    );
    let response = web_client.fetch(THREAT_FOX_URL, query_param)?;
    let response: QueryResponse = serde_json::from_str(&response)?;

    if response.query_status != "ok" {
        return Err(crate::error::Error::QueryError(response.data.to_string()))
    }

    Ok(
        serde_json::from_value::<std::collections::HashMap<String, std::collections::HashMap<String, Option<String>>>>(
            response.data
        )?
        .into_iter()
        .map(
            |(key, value)| MalwareFamily {
                name: key,
                malware_printable: value.get("malware_printable").map_or(
                    String::new(),
                    |malware_printable| malware_printable.clone().unwrap()
                ),
                malware_alias: value.get("malware_alias").map_or(
                    None,
                    |malware_alias| malware_alias.clone()
                )
            }
        )
        .collect::<Vec<MalwareFamily>>()
    )
}


#[cfg(test)]
mod tests {
    use crate::{fakers::FakeHttpReqwest, queries::{query_iocs_info, retrieve_threat_types, retrieve_tags, retrieve_malware_families}};

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

        assert!(matches!(result, crate::error::Error::QueryError(_)), "Error is not QueryError");
    }

    #[test]
    fn test_retrieve_threat_types() {
        let web_client = FakeHttpReqwest::default().set_success_response(
            include_str!("test_files/threat_types.json").to_string()
        );
        let result = retrieve_threat_types(&web_client);

        assert!(
            !result.unwrap().is_empty(),
            "Threat types cannot be empty"
        );
    }

    #[test]
    fn test_retrieve_tag_list() {
        let web_client = FakeHttpReqwest::default().set_success_response(
            include_str!("test_files/tag_list.json").to_string()
        );
        let result = retrieve_tags(&web_client);

        assert!(
            !result.unwrap().is_empty(),
            "Threat tags cannot be empty"
        );
    }

    #[test]
    fn test_retrieve_malware_families() {
        let web_client = FakeHttpReqwest::default().set_success_response(
            include_str!("test_files/malware_families.json").to_string()
        );
        let result = retrieve_malware_families(&web_client);

        assert!(
            !result.unwrap().is_empty(),
            "Malware families response cannot be empty"
        );
    }
}
