use rand::seq::SliceRandom;
use rand::thread_rng;

mod constants {
    pub const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    pub const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    pub const NUMERICAL_CHARS: &[u8] = b"0123456789";
    pub const SPECIAL_CHARS: &[u8] = b"~`!@#$%^&*()_-+={[|]}\\'\":;.,<>?/";
}

pub enum CharType {
    Lowercase,
    Uppercase,
    Numerical,
    Special,
}

trait SymbolSource {
    fn get_symbols(&self) -> &[u8];
}

impl SymbolSource for CharType {
    fn get_symbols(&self) -> &[u8] {
        match *self {
            CharType::Lowercase => constants::LOWERCASE_CHARS,
            CharType::Uppercase => constants::UPPERCASE_CHARS,
            CharType::Numerical => constants::NUMERICAL_CHARS,
            CharType::Special => constants::SPECIAL_CHARS,
        }
    }
}

pub struct Config {
    enable_lower: bool,
    enable_upper: bool,
    enable_numerical: bool,
    enable_special: bool,
    pub length: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enable_lower: true,
            enable_upper: true,
            enable_numerical: true,
            enable_special: false,
            length: 10,
        }
    }
}

use clap::{App, Arg};
impl Config {
    pub fn new(
        enable_lower: bool,
        enable_upper: bool,
        enable_numerical: bool,
        enable_special: bool,
        length: usize,
    ) -> Self {
        Config {
            enable_lower,
            enable_upper,
            enable_numerical,
            enable_special,
            length,
        }
    }
    pub fn get_state(&self, c_type: &CharType) -> bool {
        match c_type {
            CharType::Lowercase => self.enable_lower,
            CharType::Uppercase => self.enable_upper,
            CharType::Numerical => self.enable_numerical,
            CharType::Special => self.enable_special,
        }
    }
    pub fn set_state(&mut self, c_type: &CharType, state: bool) {
        match c_type {
            CharType::Lowercase => {
                self.enable_lower = state;
            }
            CharType::Uppercase => {
                self.enable_upper = state;
            }
            CharType::Numerical => {
                self.enable_numerical = state;
            }
            CharType::Special => {
                self.enable_special = state;
            }
        }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for opt in [
            CharType::Lowercase,
            CharType::Uppercase,
            CharType::Numerical,
            CharType::Special,
        ]
        .iter()
        {
            if self.get_state(&opt) {
                result.extend_from_slice(opt.get_symbols());
            }
        }
        result
    }
    pub fn from_args() -> Self {
        let matches = App::new("Password Generator")
            .about("Generate a randomized password string.")
            .arg(
                Arg::with_name("no_lower")
                    .short("l")
                    .long("no-lower")
                    .help("Disable lowercase characters ([a-z])"),
            )
            .arg(
                Arg::with_name("no_upper")
                    .short("u")
                    .long("no-upper")
                    .help("Disable uppercase characters ([A-Z])"),
            )
            .arg(
                Arg::with_name("no_number")
                    .short("n")
                    .long("no-number")
                    .help("Disable numerical characters ([0-9])"),
            )
            .arg(
                Arg::with_name("symbol")
                    .short("s")
                    .long("symbol")
                    .help("Enable symbolic characters"),
            )
            .arg(
                Arg::with_name("length")
                    .short("c")
                    .long("length")
                    .takes_value(true)
                    .value_name("LENGTH")
                    .help("The number of characters composing the password"),
            )
            .get_matches();

        Config {
            enable_lower: !matches.is_present("no_lower"),
            enable_upper: !matches.is_present("no_upper"),
            enable_numerical: !matches.is_present("no_number"),
            enable_special: matches.is_present("symbol"),
            length: match matches.value_of("length") {
                Some(l) => l.parse().expect("Invalid length argument supplied."),
                None => 10,
            },
        }
    }
}

pub trait PasswordGenerator {
    fn generate(&self, length: usize) -> String;
}

impl PasswordGenerator for Config {
    fn generate(&self, length: usize) -> String {
        let v = self.to_vec();
        let mut result = String::with_capacity(length);
        for _ in 0..length {
            result.push(*v.as_slice().choose(&mut thread_rng()).unwrap() as char);
        }
        result
    }
}

impl PasswordGenerator for &[u8] {
    fn generate(&self, length: usize) -> String {
        let mut result = String::with_capacity(length);
        for _ in 0..length {
            result.push(*self.choose(&mut thread_rng()).unwrap() as char);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_symbols() {
        assert_eq!(
            constants::LOWERCASE_CHARS,
            CharType::Lowercase.get_symbols()
        );
        assert_eq!(
            constants::UPPERCASE_CHARS,
            CharType::Uppercase.get_symbols()
        );
        assert_eq!(
            constants::NUMERICAL_CHARS,
            CharType::Numerical.get_symbols()
        );
        assert_eq!(constants::SPECIAL_CHARS, CharType::Special.get_symbols());
    }

    #[test]
    fn test_default_config() {
        let conf = Config::default();
        assert!(conf.enable_lower);
        assert!(conf.enable_upper);
        assert!(conf.enable_numerical);
        assert!(!conf.enable_special);
    }

    #[test]
    fn test_config_get_state() {
        let conf = Config::default();
        assert!(conf.get_state(&CharType::Lowercase));
        assert!(conf.get_state(&CharType::Uppercase));
        assert!(conf.get_state(&CharType::Numerical));
        assert!(!conf.get_state(&CharType::Special));
    }

    #[test]
    fn test_config_set_state() {
        let mut conf = Config::default();
        conf.set_state(&CharType::Lowercase, false);
        assert!(!conf.get_state(&CharType::Lowercase));
        assert!(conf.get_state(&CharType::Uppercase));
        assert!(conf.get_state(&CharType::Numerical));
        assert!(!conf.get_state(&CharType::Special));
        conf.set_state(&CharType::Special, true);
        assert!(!conf.get_state(&CharType::Lowercase));
        assert!(conf.get_state(&CharType::Uppercase));
        assert!(conf.get_state(&CharType::Numerical));
        assert!(conf.get_state(&CharType::Special));
        conf.set_state(&CharType::Numerical, false);
        assert!(!conf.get_state(&CharType::Lowercase));
        assert!(conf.get_state(&CharType::Uppercase));
        assert!(!conf.get_state(&CharType::Numerical));
        assert!(conf.get_state(&CharType::Special));
        conf.set_state(&CharType::Uppercase, true);
        assert!(!conf.get_state(&CharType::Lowercase));
        assert!(conf.get_state(&CharType::Uppercase));
        assert!(!conf.get_state(&CharType::Numerical));
        assert!(conf.get_state(&CharType::Special));

        conf.set_state(&CharType::Lowercase, true);
        conf.set_state(&CharType::Uppercase, false);
        conf.set_state(&CharType::Numerical, true);
        conf.set_state(&CharType::Special, false);
        assert!(conf.get_state(&CharType::Lowercase));
        assert!(!conf.get_state(&CharType::Uppercase));
        assert!(conf.get_state(&CharType::Numerical));
        assert!(!conf.get_state(&CharType::Special));
    }

    #[test]
    fn test_config_to_vec() {
        let conf = Config::new(false, false, false, false, 10);
        let empty: Vec<u8> = Vec::new();
        assert_eq!(empty, conf.to_vec());
        let mut conf = Config::new(false, false, true, false, 10);
        assert_eq!("0123456789".as_bytes().to_vec(), conf.to_vec());
        conf.set_state(&CharType::Lowercase, true);
        conf.set_state(&CharType::Uppercase, true);
        assert_eq!(
            "abcdefghijklmnopqrstuvwxyz\
             ABCDEFGHIJKLMNOPQRSTUVWXYZ\
             0123456789"
                .as_bytes()
                .to_vec(),
            conf.to_vec()
        );
        conf.set_state(&CharType::Special, true);
        assert_eq!(
            "abcdefghijklmnopqrstuvwxyz\
             ABCDEFGHIJKLMNOPQRSTUVWXYZ\
             0123456789\
             ~`!@#$%^&*()_-+={[|]}\\'\":;.,<>?/"
                .as_bytes()
                .to_vec(),
            conf.to_vec()
        );
    }
}
