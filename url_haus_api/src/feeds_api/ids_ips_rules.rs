use std::str::FromStr;

use crate::WebFetch;

const URL_HAUS_SNORT_RULES_URL: &str = "https://urlhaus.abuse.ch/downloads/ids/";
const URL_HAUS_SURICATA_RULES_URL: &str = "https://urlhaus.abuse.ch/downloads/suricata-ids/";

#[derive(Debug, Default)]
pub struct SnortRule {
    pub action: String,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: String,
    pub direction: String,
    pub dst_addr: String,
    pub dst_port: String,
    pub options: Vec<String>,
}

fn parse_snort_rule(snort_rule: &str) -> nom::IResult<&str, SnortRule> {
    let (snort_rule, action) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, protocol) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, src_addr) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, src_port) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, direction) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, dst_addr) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, dst_port) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, _) = nom::character::complete::char('(')(snort_rule)?;
    let (snort_rule, options) = nom::multi::separated_list0(
        nom::bytes::complete::tag(";"),
        nom::combinator::map(nom::bytes::complete::take_until(";"), |opt_str: &str| {
            opt_str.trim().to_string()
        }),
    )(snort_rule)?;

    Ok((
        snort_rule,
        SnortRule {
            action,
            direction,
            dst_addr,
            dst_port,
            options,
            protocol,
            src_addr,
            src_port,
        },
    ))
}

impl FromStr for SnortRule {
    type Err = crate::error::Error;

    fn from_str(snort_rule: &str) -> Result<Self, Self::Err> {
        return match parse_snort_rule(snort_rule) {
            Ok((_, rule)) => Ok(rule),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        };
    }
}

pub fn fetch_snort_rules(
    web_client: &impl WebFetch,
) -> Result<Vec<SnortRule>, crate::error::Error> {
    let response = web_client.fetch(URL_HAUS_SNORT_RULES_URL)?;

    Ok(response
        .lines()
        .skip_while(|line| line.starts_with('#'))
        .map(SnortRule::from_str)
        .filter_map(|res_snort_rule| res_snort_rule.ok())
        .collect())
}

pub fn fetch_suricata_rules(
    web_client: &impl WebFetch,
) -> Result<Vec<SnortRule>, crate::error::Error> {
    let response = web_client.fetch(URL_HAUS_SURICATA_RULES_URL)?;

    Ok(response
        .lines()
        .skip_while(|line| line.starts_with('#'))
        .map(SnortRule::from_str)
        .filter_map(|res_snort_rule| res_snort_rule.ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::fakers::FakeHttpReqwest;

    use super::*;

    const SNORT_RULE: &'static str = "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"URLhaus Known malware download URL detected (2594519)\"; flow:established,from_client; content:\"GET\"; http_method; content:\"/f7a5529f1c222f09/vcruntime140.dll\"; http_uri; depth:34; isdataat:!1,relative; nocase; content:\"5.75.232.223\"; http_host; depth:12; isdataat:!1,relative; metadata:created_at 2023_04_02; reference:url, urlhaus.abuse.ch/url/2594519/; classtype:trojan-activity;sid:83457619; rev:1;)";

    #[test]
    fn test_parse_snort_rule() -> Result<(), crate::error::Error> {
        let parsed_rule: SnortRule = SnortRule::from_str(SNORT_RULE)?;

        assert_eq!(parsed_rule.action, "alert");
        assert_eq!(parsed_rule.protocol, "http");
        assert_eq!(parsed_rule.src_addr, "$HOME_NET");
        assert_eq!(parsed_rule.src_port, "any");
        assert_eq!(parsed_rule.direction, "->");
        assert_eq!(parsed_rule.dst_addr, "$EXTERNAL_NET");
        assert_eq!(parsed_rule.dst_port, "any");
        assert!(!parsed_rule.options.is_empty());
        assert_eq!(parsed_rule.options.len(), 18);

        return Ok(());
    }

    #[test]
    fn test_fetch_url_haus_snort_rules() -> Result<(), crate::error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/snort_rules").to_string());
        let snort_rules: Vec<SnortRule> = fetch_snort_rules(&fake_reqwest)?;

        assert_eq!(snort_rules.len(), 2);

        for rule in snort_rules {
            assert_eq!(rule.action, "alert");
            assert_eq!(rule.protocol, "http");
            assert_eq!(rule.src_addr, "$HOME_NET");
            assert_eq!(rule.src_port, "any");
            assert_eq!(rule.direction, "->");
            assert_eq!(rule.dst_addr, "$EXTERNAL_NET");
            assert_eq!(rule.dst_port, "any");
            assert!(!rule.options.is_empty());
        }

        return Ok(());
    }

    #[test]
    fn test_fetch_url_haus_suricata_rules() -> Result<(), crate::error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/suricata_rules").to_string());
        let snort_rules: Vec<SnortRule> = fetch_suricata_rules(&fake_reqwest)?;

        assert_eq!(snort_rules.len(), 3);

        for rule in snort_rules {
            assert_eq!(rule.action, "alert");
            assert_eq!(rule.protocol, "http");
            assert_eq!(rule.src_addr, "$HOME_NET");
            assert_eq!(rule.src_port, "any");
            assert_eq!(rule.direction, "->");
            assert_eq!(rule.dst_addr, "$EXTERNAL_NET");
            assert_eq!(rule.dst_port, "any");
            assert!(!rule.options.is_empty());
        }

        return Ok(());
    }
}
