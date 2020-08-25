fn main() {
    use lib::{Config, PasswordGenerator};
    println!("Generating Password...");
    let config = Config::from_args();
    println!("{}", config.generate(10));
}
