pub mod error;
pub mod feeds_api;


pub trait WebFetch {
    fn fetch(&self, url: &str) -> Result<String, error::Error>;
}

#[derive(Default)]
pub struct HttpReqwest;

impl WebFetch for HttpReqwest {
    fn fetch(&self, url: &str) -> Result<String, error::Error> {
        match reqwest::blocking::get(url) {
            Ok(get_response) => match get_response.error_for_status() {
                Ok(resp) => match resp.text() {
                    Ok(text) => Ok(text),
                    Err(err) => Err(error::Error::from(err))
                },
                Err(err) => Err(error::Error::from(err))
            },
            Err(err) => Err(error::Error::from(err))
        }
    }
}

#[cfg(test)]
mod fakers {
    use super::WebFetch;
    use super::error::Error;

    #[derive(Default)]
    pub struct FakeHttpReqwest {
        success_response: String,
        error_response: Option<Error>
    }
    
    impl FakeHttpReqwest {
    
        pub fn set_success_response(mut self, response: String) -> Self {
            self.success_response = response;
    
            return self;
        }
    
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