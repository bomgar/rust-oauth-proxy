
use url::form_urlencoded;
use rand;
use rand::Rng;
use base64;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;
use time;

const OAUTH_VERSION: &'static str = "1.0";
const OAUTH_SIGNATURE_METHOD: &'static str = "HMAC-SHA1";
type ParameterList<'a> = Vec<(&'a str, &'a str)>;

#[derive(Debug, PartialEq)]
pub struct OAuthHeaders<'a> {
  oauth_version: &'a str,
  oauth_signature_method: &'a str,
  oauth_nonce: String,
  oauth_timestamp: String,
  oauth_consumer_key: &'a str,
  oauth_signature: String,
  oauth_token: Option<&'a str>,
}

impl<'a> ToString for OAuthHeaders<'a> {
  fn to_string(&self) -> String {
    // maybe add empty realm
    format!("OAuth oauth_version=\"{}\",oauth_consumer_key=\"{}\",oauth_token=\"{}\",\
             oauth_timestamp=\"{}\",oauth_nonce=\"{}\",oauth_signature_method=\"{}\",\
             oauth_signature=\"{}\"",
            url_encode(self.oauth_version),
            url_encode(self.oauth_consumer_key),
            url_encode(self.oauth_token.unwrap_or("")),
            url_encode(&self.oauth_timestamp),
            url_encode(&self.oauth_nonce),
            url_encode(self.oauth_signature_method),
            url_encode(&self.oauth_signature))
  }
}

pub fn create_auth_header<'a>(method: &'a str,
                              base_url: &'a str,
                              query_parameters: &'a ParameterList,
                              oauth_consumer_key: &'a str,
                              oauth_consumer_secret: &'a str,
                              oauth_token: Option<&'a str>,
                              oauth_token_secret: Option<&'a str>)
                              -> OAuthHeaders<'a> {
  let oauth_nonce = generate_nonce();
  let oauth_timestamp = time::now_utc().to_timespec().sec.to_string();
  let signature = create_signature(method,
                        base_url,
                        query_parameters,
                        &oauth_nonce,
                        &oauth_timestamp,
                        oauth_consumer_key,
                        oauth_consumer_secret,
                        oauth_token,
                        oauth_token_secret);
  let oauth_headers = OAuthHeaders {
    oauth_version: "1.0",
    oauth_signature_method: OAUTH_SIGNATURE_METHOD,
    oauth_nonce: oauth_nonce.to_string(),
    oauth_timestamp: oauth_timestamp.to_string(),
    oauth_consumer_key: oauth_consumer_key,
    oauth_signature: signature,
    oauth_token: oauth_token,
  };
  oauth_headers
}

pub fn create_signature(method: &str,
                        base_url: &str,
                        query_parameters: &ParameterList,
                        oauth_nonce: &str,
                        oauth_timestamp: &str,
                        oauth_consumer_key: &str,
                        oauth_consumer_secret: &str,
                        oauth_token: Option<&str>,
                        oauth_token_secret: Option<&str>)
                        -> String {
  let key = format!("{}&{}",
                    oauth_consumer_secret,
                    oauth_token_secret.unwrap_or(""));
  let mut request_params: ParameterList = query_parameters.clone();
  request_params.push(("oauth_nonce", oauth_nonce));
  request_params.push(("oauth_consumer_key", oauth_consumer_key));
  request_params.push(("oauth_timestamp", oauth_timestamp));
  request_params.push(("oauth_version", OAUTH_VERSION));
  request_params.push(("oauth_signature_method", OAUTH_SIGNATURE_METHOD));
  if let Some(t) = oauth_token {
    request_params.push(("oauth_token", t));
  }

  let base_string = build_signature_base_string(method, base_url, &request_params);
  println!("signing: '{}'", base_string);
  let signature = hmac_sha1(key.as_bytes(), base_string.as_bytes());
  base64::encode(&signature.code())
}

pub fn generate_nonce() -> String {
  rand::thread_rng()
    .gen_ascii_chars()
    .take(10)
    .collect::<String>()
}

pub fn build_signature_base_string(method: &str,
                                   base_url: &str,
                                   request_parameters: &ParameterList)
                                   -> String {

  let encoded_base_url = url_encode(base_url);
  let parameter_string = parameters_to_parameter_string(request_parameters);
  let encoded_parameter_string = url_encode(&parameter_string);
  let base_string = format!("{}&{}&{}",
                            method.to_uppercase(),
                            encoded_base_url,
                            encoded_parameter_string);
  base_string
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> MacResult {
  let mut hmac = Hmac::new(Sha1::new(), key);
  hmac.input(data);
  hmac.result()
}

fn parameters_to_parameter_string(parameters: &Vec<(&str, &str)>) -> String {
  let encoded_parameters = encode_parameters(parameters);
  let mut encoded_parameter_list = encoded_parameters.iter()
    .map(|t| t.0.to_string() + "=" + &t.1)
    .collect::<Vec<String>>();
  encoded_parameter_list.sort();
  encoded_parameter_list.join("&")
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
  let encoded = form_urlencoded::byte_serialize(string.as_bytes()).collect::<String>();
  encoded.replace("+", "%20")
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn build_a_signature_base_string() {
    let base_url = "http://example.com/request";
    let request_parameters =
      vec![("b5", "=%3D"), ("a3", "a"), ("c@", ""), ("a2", "r b"), ("c2", ""), ("a3", "2 q")];


    let expected_signature_base_string =
      String::new() + "GET&" + "http%3A%2F%2Fexample.com%2Frequest" + "&a2%3Dr%2520b%26" +
      "a3%3D2%2520q%26" + "a3%3Da%26" + "b5%3D%253D%25253D%26" + "c%2540%3D%26" + "c2%3D";

    let signature = build_signature_base_string("GET", base_url, &request_parameters);
    assert_eq!(signature, expected_signature_base_string);
  }

  #[test]
  fn should_format_an_oauth_header() {
    let oauth_headers = OAuthHeaders {
      oauth_version: "1.0",
      oauth_signature_method: super::OAUTH_SIGNATURE_METHOD,
      oauth_nonce: "kllo9940pd9333jh".to_string(),
      oauth_timestamp: "1191242096".to_string(),
      oauth_consumer_key: "dpf43f3p2l4k3l03",
      oauth_signature: "wPkvxykrw+BTdCcGqKr+3I+PsiM=".to_string(),
      oauth_token: Some("nnch734d00sl2jdk"),
    };
    let expected_header = "OAuth oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",\
                           oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1191242096\",\
                           oauth_nonce=\"kllo9940pd9333jh\",oauth_signature_method=\"HMAC-SHA1\",\
                           oauth_signature=\"wPkvxykrw%2BBTdCcGqKr%2B3I%2BPsiM%3D\"";
    assert_eq!(expected_header, oauth_headers.to_string());
  }

  #[test]
  fn should_build_correct_signature() {
    let method = "POST";
    let base_url = "http://photos.example.net/photos";
    let parameters = vec![("file", "vacation.jpg"), ("size", "original")];

    let oauth_headers = OAuthHeaders {
      oauth_version: "1.0",
      oauth_signature_method: super::OAUTH_SIGNATURE_METHOD,
      oauth_nonce: "kllo9940pd9333jh".to_string(),
      oauth_timestamp: "1191242096".to_string(),
      oauth_consumer_key: "dpf43f3p2l4k3l03",
      oauth_signature: "wPkvxykrw+BTdCcGqKr+3I+PsiM=".to_string(),
      oauth_token: Some("nnch734d00sl2jdk"),
    };

    let base_string = build_signature_base_string(method, base_url, &parameters);
    assert_eq!(base_string,
               "POST&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.\
                jpg%26size%3Doriginal");


    let signature = create_signature(method,
                                     base_url,
                                     &parameters,
                                     &oauth_headers.oauth_nonce,
                                     &oauth_headers.oauth_timestamp,
                                     oauth_headers.oauth_consumer_key,
                                     "kd94hf93k423kf44",
                                     oauth_headers.oauth_token,
                                     Some("pfkkdhi9sl3r4s00"));
    assert_eq!(signature, oauth_headers.oauth_signature)
  }

}
