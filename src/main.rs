fn main() {
    use lib::{Config, PasswordGenerator};
    println!("Generating Password...");
    let config = Config::default();
    println!("{}", config.generate(10));
}
