//! # URL Haus API
//!
//! A Rust client library for interacting with the URL Haus API from Spamhaus Abuse.ch.
//! This library provides types and functions to fetch various threat intelligence feeds
//! including malicious URLs, DNS RPZ records, host files, and IDS/IPS rules.
//!
//! ## Modules
//!
//! - [`error`]: Error types used throughout the library
//! - [`feeds_api`]: Feed retrieval operations for various data formats

pub mod error;
pub mod feeds_api;

/// Trait for fetching data from web endpoints.
///
/// This trait abstracts HTTP client implementations, allowing for different transport layers
/// (e.g., reqwest, hyper, or mock implementations for testing).
pub trait WebFetch {
    /// Fetches data from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The endpoint URL to request
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
    fn fetch(&self, url: &str) -> Result<String, error::Error>;
}

/// HTTP client implementation using the reqwest library.
///
/// Provides a concrete implementation of the [`WebFetch`] trait using the blocking reqwest HTTP client.
/// This is the default HTTP client implementation for production use.
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, WebFetch, feeds_api::urls_db::fetch_recent_urls};
///
/// let client = HttpReqwest::default();
/// let urls = fetch_recent_urls(&client)?;
/// ```
#[derive(Default)]
pub struct HttpReqwest;

impl WebFetch for HttpReqwest {
    fn fetch(&self, url: &str) -> Result<String, error::Error> {
        match reqwest::blocking::get(url) {
            Ok(get_response) => match get_response.error_for_status() {
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
    ///     .set_success_response("response data".to_string());
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
        /// * `response` - A string representing the API response
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
        fn fetch(&self, _: &str) -> Result<String, Error> {
            if let Some(err) = &self.error_response {
                return Err(err.clone());
            }

            return Ok(self.success_response.clone());
        }
    }
}
