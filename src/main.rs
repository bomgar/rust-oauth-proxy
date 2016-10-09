extern crate url;
extern crate rand;
extern crate base64;
extern crate crypto;
extern crate clap;

mod oauth;

use oauth::hello;
use clap::{Arg, App, AppSettings};

fn main() {
  App::new("rust oauth proxy")
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
}
