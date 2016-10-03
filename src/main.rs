extern crate url;

mod oauth;

use oauth::hello;

fn main() {
  println!("{}", hello());
}
