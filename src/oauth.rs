use url::form_urlencoded;

pub fn hello() -> &'static str {
  return "hello";
}

pub fn build_signature_base_string(method: &str,
                                   base_url: &str,
                                   request_parameters: &Vec<(&str, &str)>)
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

}
