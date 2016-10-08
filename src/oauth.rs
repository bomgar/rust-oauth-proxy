use url::form_urlencoded;
use rand;
use rand::Rng;
use base64;

const OAUTH_VERSION: &'static str = "1.0";
const OAUTH_SIGNATURE_METHOD: &'static str = "HMAC-SHA1";
type ParameterList<'a> = Vec<(&'a str, &'a str)>;

#[derive(Debug, PartialEq)]
pub struct OAuthHeaders<'a> {
  oauth_version: &'a str,
  oauth_signature_method: &'a str,
  oauth_nonce: &'a str,
  oauth_timestamp: &'a str,
  oauth_consumer_key: &'a str,
  oauth_signature: &'a str
}

pub fn hello() -> &'static str {
  return "hello";
}

pub fn create_signature(method: &str, base_url: &str, query_parameters: &ParameterList, oauth_nonce: &str, oauth_timestamp: &str, oauth_consumer_key: &str) -> String {
  let mut request_params: ParameterList = query_parameters.clone();
  request_params.push(("oauth_nonce", oauth_nonce));
  request_params.push(("oauth_consumer_key", oauth_consumer_key));
  request_params.push(("oauth_timestamp", oauth_timestamp));
  request_params.push(("oauth_version", OAUTH_VERSION));
  request_params.push(("oauth_signature_method", OAUTH_SIGNATURE_METHOD));
  build_signature_base_string(method, base_url, &request_params);
  "".to_string()
}

pub fn generate_nonce() -> String {
  let mut rng = rand::thread_rng();
  let mut nonce_bytes: [u8; 16] = [0; 16];
  rng.fill_bytes(&mut nonce_bytes);
  base64::encode(&nonce_bytes)
}

pub fn build_signature_base_string(method: &str,
                                   base_url: &str,
                                   request_parameters: &ParameterList)
                                   -> String {

  let encoded_base_url = url_encode(base_url);
  let parameter_string = parameters_to_parameter_string(request_parameters);
  let encoded_parameter_string = url_encode(&parameter_string);
  let base_string = format!("{}&{}&{}", method.to_uppercase(), encoded_base_url, encoded_parameter_string);
  base_string
}

fn parameters_to_parameter_string(parameters: &Vec<(&str, &str)>) -> String {
  let mut encoded_parameters = encode_parameters(parameters);
  encoded_parameters.sort_by(|a, b| a.0.cmp(&b.0));
  encoded_parameters.iter()
    .map(|t| {t.0.to_string() + "=" + &t.1})
    .collect::<Vec<String>>()
    .join("&")
}
fn encode_parameters(parameters: &Vec<(&str, &str)>) -> Vec<(String, String)> {
  parameters.iter()
    .map(|t| {
      let key = url_encode(t.0);
      let value = url_encode(t.1);
      (key, value)
    })
    .collect::<Vec<_>>()
}

fn url_encode(string: &str) -> String {
  form_urlencoded::byte_serialize(string.as_bytes()).collect::<String>()
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn build_a_signature_base_string() {
    let request_parameters = vec![("b", "1"), ("a", "2")];
    let signature =
      build_signature_base_string("GET", "https://test.test.org/moep", &request_parameters);
    assert_eq!(signature, "GET&https%3A%2F%2Ftest.test.org%2Fmoep&a%3D2%26b%3D1");
  }


  #[test]
  fn should_build_correct_signature() {
    let expected_oauth_headers = OAuthHeaders {
      oauth_version: "1.0",
      oauth_signature_method: super::OAUTH_SIGNATURE_METHOD,
      oauth_nonce: "A7Dl0UO1Yl2I8EA",
      oauth_timestamp: "1475676416",
      oauth_consumer_key: "hello-key",
      oauth_signature: "VAhLqfwl4qsN%2F13vYotEdMWDjH0%3D"
    };
    assert_eq!(expected_oauth_headers, expected_oauth_headers)
  }

}
