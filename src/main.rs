use clap::Parser;
use tower_http::trace::TraceLayer;

use encryption_oracle::api;
use encryption_oracle::config::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = Config::parse();
    let app = api::app().layer(TraceLayer::new_for_http());

    tracing::info!("listening on {}", config.bind);
    let listener = tokio::net::TcpListener::bind(config.bind).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
