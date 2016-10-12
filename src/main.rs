extern crate url;
extern crate rand;
extern crate base64;
extern crate crypto;
extern crate clap;
extern crate time;
extern crate hyper;
#[macro_use]
extern crate slog;
extern crate slog_term;


mod oauth;

use rand::Rng;
use slog::DrainExt;
use slog::Logger;
use clap::{Arg, App, AppSettings};
use hyper::server::{Server, Request, Response};
use hyper::client::Client;
use std::net::ToSocketAddrs;
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

fn main() {
  let matches = App::new("rust oauth proxy")
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
    .get_matches();
  let port = matches.value_of("port").unwrap();
  let oauth_parameters = OauthParameters {
    oauth_consumer_key: matches.value_of("consumer-key").unwrap().to_string(),
    oauth_consumer_secret: matches.value_of("consumer-secret").unwrap().to_string(),
    oauth_token: matches.value_of("token").map(|s| s.to_string()),
    oauth_token_secret: matches.value_of("token-secret").map(|s| s.to_string())
  };



  let bind_address = format!("0.0.0.0:{}", port).to_socket_addrs().unwrap().collect::<Vec<_>>()[0];

  let log = slog::Logger::root(slog_term::streamer().full().build().fuse(), o!());

  debug!(log, "Using oauth parameters"; "oauth_parameters" => format!("{:?}", oauth_parameters));


  let bind_result = Server::http(bind_address);
  if let Ok(server) = bind_result {
    info!(log, "Server started."; "bind_address" => bind_address.to_string());
    server.handle(move |request: Request, response: Response| {
        let log = log.new(o!("correlation_id" => create_correlation_id()));
        if let Err(e) = proxy_request(&log, request, response) {
          error!(log, "{}", e)
        }
      })
      .unwrap();
  } else {
    crit!(log, "Failed to bind server."; "bind_address" => bind_address.to_string());
  }
}

fn proxy_request(log: &Logger, request: Request, mut response: Response) -> Result<(), ProxyError> {
  info!(log, "Incoming request";
              "from" => request.remote_addr.to_string(),
              "method" => request.method.to_string(),
              "uri" => request.uri.to_string()
      );
  let auth_header = generate_oauth_header_for_request(log, &request);
  let client = Client::new();
  let mut proxy_response = try!(client.request(request.method, &request.uri.to_string()).send());
  *response.status_mut() = proxy_response.status.clone();
  *response.headers_mut() = proxy_response.headers.clone();
  let mut response = try!(response.start());
  try!(std::io::copy(&mut proxy_response, &mut response));
  try!(response.end());
  Ok(())
}

fn generate_oauth_header_for_request(log: &Logger,
                                     request: &Request)
                                     -> Result<String, ProxyError> {
  let method = request.method.to_string().to_uppercase();
  if let RequestUri::AbsoluteUri(url) = request.uri.clone() {
    debug!(log, ""; "query" => url.query(), "method" => method);
    let query_parameters = extract_query_params(&url);
    Ok("".to_string())
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

fn create_correlation_id() -> String {
  rand::thread_rng()
    .gen_ascii_chars()
    .take(20)
    .collect::<String>()
}
