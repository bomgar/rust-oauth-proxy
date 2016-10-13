extern crate url;
extern crate rand;
extern crate base64;
extern crate crypto;
extern crate clap;
extern crate time;
#[macro_use]
extern crate hyper;
#[macro_use]
extern crate slog;
extern crate slog_term;


mod oauth;

use rand::Rng;
use slog::{Logger, LevelFilter, Level, DrainExt};
use clap::{Arg, App, AppSettings};
use hyper::server::{Server, Request, Response};
use hyper::client::Client;
use hyper::method::Method;
use hyper::header::Headers;
use hyper::uri::RequestUri;
use url::Url;

use std::error::Error;
use std::fmt;
use std::convert::From;

#[derive(Debug)]
struct ProxyError {
  message: String,
}

impl fmt::Display for ProxyError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.message)
  }
}

impl Error for ProxyError {
  fn description(&self) -> &str {
    &self.message
  }
}

impl From<hyper::Error> for ProxyError {
  fn from(e: hyper::Error) -> ProxyError {
    ProxyError { message: format!("{}", e) }
  }
}

impl From<std::io::Error> for ProxyError {
  fn from(e: std::io::Error) -> ProxyError {
    ProxyError { message: format!("{}", e) }
  }
}

#[derive(Debug)]
struct OauthParameters {
  oauth_consumer_key: String,
  oauth_consumer_secret: String,
  oauth_token: Option<String>,
  oauth_token_secret: Option<String>,
}

header! { (Authorization, "Authorization") => [String] }

fn main() {
  let matches: clap::ArgMatches = create_app().get_matches();
  let port = matches.value_of("port").unwrap();
  let verbose: bool = matches.is_present("verbose");
  let oauth_parameters = build_oauth_parameters(&matches);
  let bind_address: &str = &format!("0.0.0.0:{}", port);

  let stream = slog_term::streamer().full().build();
  let log = if verbose {
    slog::Logger::root(stream.fuse(), o!())
  } else {
    slog::Logger::root(LevelFilter::new(stream, Level::Info).fuse(), o!())
  };

  debug!(log, "Using oauth parameters"; "oauth_parameters" => format!("{:?}", oauth_parameters));

  let bind_result = Server::http(&bind_address);
  if let Ok(server) = bind_result {
    info!(log, "Server started."; "bind_address" => bind_address.to_string());
    server.handle(move |request: Request, response: Response| {
        let log = log.new(o!("correlation_id" => create_correlation_id()));
        if let Err(e) = proxy_request(&log, request, response, &oauth_parameters) {
          error!(log, "{}", e)
        }
      })
      .unwrap();
  } else {
    crit!(log, "Failed to bind server."; "bind_address" => bind_address.to_string());
  }
}

fn build_oauth_parameters(matches: &clap::ArgMatches) -> OauthParameters {
  OauthParameters {
    oauth_consumer_key: matches.value_of("consumer-key").unwrap().to_string(),
    oauth_consumer_secret: matches.value_of("consumer-secret").unwrap().to_string(),
    oauth_token: matches.value_of("token").map(|s| s.to_string()),
    oauth_token_secret: matches.value_of("token-secret").map(|s| s.to_string()),
  }
}

fn create_app<'a>() -> App<'a, 'a> {
  App::new("rust oauth proxy")
    .version("0.1")
    .setting(AppSettings::ColoredHelp)
    .author("Patrick Haun <bomgar85@googlemail.com>")
    .about("provides a http proxy to authenticate requests using oauth.")
    .arg(Arg::with_name("port")
      .short("p")
      .long("port")
      .value_name("PORT")
      .help("bind proxy to port")
      .required(true)
      .takes_value(true))
    .arg(Arg::with_name("consumer-key")
      .short("k")
      .long("consumer-key")
      .value_name("CONSUMER_KEY")
      .help("oauth consumer key")
      .required(true)
      .takes_value(true))
    .arg(Arg::with_name("consumer-secret")
      .short("s")
      .long("consumer-secret")
      .value_name("CONSUMER_SECRET")
      .help("oauth consumer secret")
      .required(true)
      .takes_value(true))
    .arg(Arg::with_name("token")
      .long("token")
      .value_name("TOKEN")
      .help("oauth token")
      .required(false)
      .takes_value(true))
    .arg(Arg::with_name("token-secret")
      .long("token-secret")
      .value_name("TOKEN_SECRET")
      .help("oauth token secret")
      .required(false)
      .takes_value(true))
    .arg(Arg::with_name("verbose")
      .long("verbose")
      .short("v")
      .help("debug output")
      .required(false)
      .takes_value(false))
}

fn proxy_request(log: &Logger,
                 request: Request,
                 mut response: Response,
                 oauth_parameters: &OauthParameters)
                 -> Result<(), ProxyError> {
  info!(log, "Incoming request";
              "from" => request.remote_addr.to_string(),
              "method" => request.method.to_string(),
              "uri" => request.uri.to_string()
      );
  let auth_header = try!(generate_oauth_header_for_request(log, &request, oauth_parameters));
  let mut headers: Headers = request.headers.clone();
  headers.set(Authorization(auth_header));
  match send_request(request.method, &request.uri.to_string(), headers) {
    Ok(mut proxy_response) => {
      *response.status_mut() = proxy_response.status.clone();
      *response.headers_mut() = proxy_response.headers.clone();
      let mut response = try!(response.start());
      try!(std::io::copy(&mut proxy_response, &mut response));
      try!(response.end());
      Ok(())
    }
    Err(e) => {
      error!(log, "Request to remote server failed {}", e);
      *response.status_mut() = hyper::status::StatusCode::InternalServerError;
      Ok(())

    }
  }
}

fn send_request(method: Method,
                uri: &str,
                headers: Headers)
                -> Result<hyper::client::Response, ProxyError> {
  let client = Client::new();
  let response = try!(client.request(method, uri).headers(headers).send());
  Ok(response)
}

fn generate_oauth_header_for_request(log: &Logger,
                                     request: &Request,
                                     oauth_parameters: &OauthParameters)
                                     -> Result<String, ProxyError> {
  let method = request.method.to_string().to_uppercase();
  if let RequestUri::AbsoluteUri(url) = request.uri.clone() {
    let base_url = extract_base_url(&url);
    debug!(log, ""; "query" => url.query(), "method" => method, "base_url" => base_url);
    let query_parameters = extract_query_params(&url);
    let oauth_headers =
      oauth::create_auth_header(&method,
                                &base_url,
                                &query_parameters,
                                &oauth_parameters.oauth_consumer_key,
                                &oauth_parameters.oauth_consumer_secret,
                                oauth_parameters.oauth_token.as_ref().map(|x| &**x),
                                oauth_parameters.oauth_token_secret.as_ref().map(|x| &**x));
    debug!(log, "Calculated oauth headers"; "oauth headers" => oauth_headers.to_string());
    Ok(oauth_headers.to_string())
  } else {
    Err(ProxyError { message: "Require absolute url.".to_string() })
  }
}

fn extract_query_params(url: &Url) -> Vec<(String, String)> {
  url.query_pairs()
    .map(|pair| {
      let (key_cow, value_cow) = pair;
      (key_cow.into_owned(), value_cow.into_owned())
    })
    .collect::<Vec<_>>()
}

#[test]
fn test_extract_query_params() {
  let url = url::Url::parse("http://is24.de/test?a=a&b=c").unwrap();
  let query_params = extract_query_params(&url);
  assert_eq!(vec![("a".to_string(), "a".to_string()), ("b".to_string(), "c".to_string())],
             query_params)
}

fn extract_base_url(url: &url::Url) -> String {
  let base_url = url.to_string()
    .replace(&url.query()
               .map(|s| "?".to_string() + s)
               .unwrap_or("".to_string()),
             "");
  base_url
}


#[test]
fn test_extract_base_url() {
  let url = url::Url::parse("http://is24.de/test?a=a&b=b").unwrap();
  let base_url = extract_base_url(&url);
  assert_eq!("http://is24.de/test", base_url)
}

fn create_correlation_id() -> String {
  rand::thread_rng()
    .gen_ascii_chars()
    .take(20)
    .collect::<String>()
}
