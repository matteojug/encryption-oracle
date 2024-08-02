#[derive(clap::Parser)]
pub struct Config {
    #[clap(long, env, default_value = "localhost:3000")]
    pub bind: String,
}
