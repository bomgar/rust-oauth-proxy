extern crate url;
extern crate rand;
extern crate base64;

mod oauth;

use oauth::hello;

fn main() {
  println!("{}", hello());
}
