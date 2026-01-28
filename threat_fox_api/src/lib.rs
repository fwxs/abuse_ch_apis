//! # Threat Fox API
//!
//! A Rust client library for interacting with the Threat Fox API from Spamhaus Abuse.ch.
//! This library provides types and functions to query indicators of compromise (IoCs),
//! retrieve threat intelligence, and access threat types, tags, and malware families.
//!
//! ## Modules
//!
//! - [`error`]: Error types used throughout the library
//! - [`queries`]: Query operations and response structures for the Threat Fox API

pub mod error;
pub mod queries;

/// Trait for fetching data from web endpoints.
///
/// This trait abstracts HTTP client implementations, allowing for different transport layers
/// (e.g., reqwest, hyper, or mock implementations for testing).
pub trait WebFetch {
    /// Fetches data from a URL with the given JSON body parameters.
    ///
    /// # Arguments
    ///
    /// * `url` - The API endpoint URL to request
    /// * `json_body` - A HashMap of JSON body parameters to send with the request
    ///
    /// # Returns
    ///
    /// Returns the response body as a string on success, or an [`error::Error`] on failure.
    ///
    /// # Errors
    ///
    /// This method can fail due to:
    /// - Network errors (connection issues, timeouts, etc.)
    /// - HTTP errors (4xx, 5xx status codes)
    /// - Response parsing errors
    fn fetch(
        &self,
        url: &str,
        json_body: std::collections::HashMap<&str, String>,
    ) -> Result<String, error::Error>;
}

/// HTTP client implementation using the reqwest library.
///
/// Provides a concrete implementation of the [`WebFetch`] trait using the blocking reqwest HTTP client.
/// This is the default HTTP client implementation for production use.
///
/// # Example
///
/// ```ignore
/// use threat_fox_api::{HttpReqwest, WebFetch, queries::IoCQueryType};
///
/// let client = HttpReqwest::default();
/// let query = IoCQueryType::GetRecentIoCs(2);
/// ```
#[derive(Default)]
pub struct HttpReqwest;

impl WebFetch for HttpReqwest {
    fn fetch(
        &self,
        url: &str,
        json_body: std::collections::HashMap<&str, String>,
    ) -> Result<String, error::Error> {
        match reqwest::blocking::Client::new()
            .post(url)
            .json(&json_body)
            .send()
        {
            Ok(post_response) => match post_response.error_for_status() {
                Ok(resp) => match resp.text() {
                    Ok(text) => Ok(text),
                    Err(err) => Err(error::Error::from(err)),
                },
                Err(err) => Err(error::Error::from(err)),
            },
            Err(err) => Err(error::Error::from(err)),
        }
    }
}

#[cfg(test)]
pub mod fakers {
    use super::error::Error;
    use super::WebFetch;

    /// Mock HTTP client for testing purposes.
    ///
    /// Allows tests to inject predefined responses or errors without making actual network requests.
    /// Use the builder methods [`set_success_response`] and [`set_error_response`] to configure behavior.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fake_client = FakeHttpReqwest::default()
    ///     .set_success_response(r#"{"query_status":"ok","data":[]}"#.to_string());
    /// ```
    #[derive(Default)]
    pub struct FakeHttpReqwest {
        /// The successful response to return from fetch calls.
        success_response: String,
        /// Optional error to return instead of success response.
        error_response: Option<Error>,
    }

    impl FakeHttpReqwest {
        /// Sets the success response that will be returned by the mock client.
        ///
        /// # Arguments
        ///
        /// * `response` - A JSON string representing the API response
        ///
        /// # Returns
        ///
        /// Returns self for method chaining.
        pub fn set_success_response(mut self, response: String) -> Self {
            self.success_response = response;

            return self;
        }

        /// Sets an error that will be returned by the mock client instead of a success response.
        ///
        /// # Arguments
        ///
        /// * `error` - An [`error::Error`] to return from fetch calls
        ///
        /// # Returns
        ///
        /// Returns self for method chaining.
        pub fn set_error_response(mut self, error: Error) -> Self {
            self.error_response = Some(error);

            return self;
        }
    }

    impl WebFetch for FakeHttpReqwest {
        fn fetch(
            &self,
            _: &str,
            _: std::collections::HashMap<&str, String>,
        ) -> Result<String, crate::error::Error> {
            if let Some(err) = &self.error_response {
                return Err(err.clone());
            }

            return Ok(self.success_response.clone());
        }
    }
}
