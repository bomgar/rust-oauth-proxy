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
use hyper::client::{Client};
use std::net::ToSocketAddrs;

fn main() {
  let matches = App::new("rust oauth proxy")
    .version("0.1")
    .setting(AppSettings::ColoredHelp)
    .author("Patrick Haun <bomgar85@googlemail.com>")
    .about("provides a http proxy to authenticate requests.")
    .arg(Arg::with_name("port")
      .short("p")
      .long("port")
      .value_name("PORT")
      .help("bind proxy to port")
      .required(true)
      .takes_value(true))
    .get_matches();
  let port = matches.value_of("port").unwrap();

  let bind_address = format!("0.0.0.0:{}", port).to_socket_addrs().unwrap().collect::<Vec<_>>()[0];

  let log = slog::Logger::root(slog_term::streamer().full().build().fuse(), o!());


  let bind_result = Server::http(bind_address);
  if let Ok(server) = bind_result {
    info!(log, "Server started."; "bind_address" => bind_address.to_string());
    server.handle(move |request: Request, response: Response| {
        let log = log.new(o!("correlation_id" => create_correlation_id()));
        proxy_request(log, request, response);
      })
      .unwrap();
  } else {
    crit!(log, "Failed to bind server."; "bind_address" => bind_address.to_string());
  }
}

fn proxy_request(log: Logger, request: Request, mut response: Response) {
  info!(log, "Incoming request";
              "from" => request.remote_addr.to_string(),
              "method" => request.method.to_string(),
              "uri" => request.uri.to_string()
      );
  let client = Client::new();
  let mut proxy_response = client.get("http://google.com/").send().unwrap();
  *response.status_mut() = proxy_response.status.clone();
  *response.headers_mut() = proxy_response.headers.clone();
  let mut response = response.start().unwrap();
  std::io::copy(&mut proxy_response, &mut response).unwrap();
  response.end().unwrap();
}

fn create_correlation_id() -> String {
  rand::thread_rng()
    .gen_ascii_chars()
    .take(20)
    .collect::<String>()
}
