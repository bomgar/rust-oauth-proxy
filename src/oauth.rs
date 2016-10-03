use url::form_urlencoded;

pub fn hello() -> &'static str {
  return "hello";
}

pub fn build_signature_base_string(method: &str, base_url: &str) -> String {

  let encoded_base_url = url_encode(base_url);
  let base_string = format!("{}&{}", method.to_uppercase(), encoded_base_url);
  return base_string;
}

fn url_encode(string: &str) -> String {
  form_urlencoded::byte_serialize(string.as_bytes()).collect::<String>()
}


#[cfg(test)]
mod tests {
   use super::*;

  #[test]
  fn build_a_signature_base_string() {
    let signature = build_signature_base_string("GET", "https://test.test.org/moep");
    assert_eq!(signature, "GET&https%3A%2F%2Ftest.test.org%2Fmoep");
  }

}
