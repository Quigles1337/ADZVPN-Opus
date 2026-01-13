//! Silver VPN Server Binary
//!
//! Command-line interface for running the ADZVPN-Opus server.
//!
//! ## Usage
//!
//! ```bash
//! silver-vpn-server --port 51820 --max-clients 256
//! ```
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

use clap::Parser;
use silver_server::{ServerConfig, SilverServer};
use std::path::PathBuf;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

/// Silver VPN Server - AI-Integrated VPN with Silver Ratio Cryptography
#[derive(Parser, Debug)]
#[command(name = "silver-vpn-server")]
#[command(author = "ADZ (Alexander David Zalewski) & Claude Opus 4.5")]
#[command(version = "0.1.0")]
#[command(about = "ADZVPN-Opus VPN Server with Silver Protocol", long_about = None)]
struct Args {
    /// Bind address
    #[arg(short = 'a', long, default_value = "0.0.0.0")]
    address: String,

    /// Bind port
    #[arg(short = 'p', long, default_value_t = 51820)]
    port: u16,

    /// Maximum number of clients
    #[arg(short = 'm', long, default_value_t = 256)]
    max_clients: usize,

    /// Configuration file path
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Disable traffic shaping
    #[arg(long)]
    no_traffic_shaping: bool,

    /// Disable timing obfuscation
    #[arg(long)]
    no_timing_obfuscation: bool,

    /// Target bandwidth in MB/s
    #[arg(long, default_value_t = 10)]
    bandwidth: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, default_value = "info")]
    log_level: String,

    /// Generate sample configuration file
    #[arg(long)]
    generate_config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();

    // Handle generate-config option
    if let Some(path) = args.generate_config {
        let config = ServerConfig::default();
        config.save_to_file(&path)?;
        println!("Generated sample configuration at: {}", path.display());
        return Ok(());
    }

    // Load or build configuration
    let config = if let Some(config_path) = args.config {
        info!("Loading configuration from: {}", config_path.display());
        ServerConfig::load_from_file(&config_path)?
    } else {
        ServerConfig::builder()
            .bind_address(&args.address)
            .bind_port(args.port)
            .max_clients(args.max_clients)
            .traffic_shaping(!args.no_traffic_shaping)
            .timing_obfuscation(!args.no_timing_obfuscation)
            .target_bandwidth(args.bandwidth * 1_000_000) // Convert MB/s to bytes/s
            .log_level(&args.log_level)
            .build()?
    };

    // Print banner
    print_banner();

    info!("Configuration:");
    info!("  Bind: {}:{}", config.bind_address, config.bind_port);
    info!("  Max clients: {}", config.max_clients);
    info!("  Traffic shaping: {}", config.enable_traffic_shaping);
    info!("  Timing obfuscation: {}", config.enable_timing_obfuscation);

    // Create and start server
    let server = SilverServer::new(config);

    // Handle Ctrl+C
    let server_clone = server.running_flag();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received shutdown signal");
        server_clone.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    // Run the server
    match server.start().await {
        Ok(()) => {
            info!("Server stopped gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(e.into())
        }
    }
}

fn print_banner() {
    println!(r#"
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   ███████╗██╗██╗  ██╗   ██╗███████╗██████╗                    ║
  ║   ██╔════╝██║██║  ██║   ██║██╔════╝██╔══██╗                   ║
  ║   ███████╗██║██║  ██║   ██║█████╗  ██████╔╝                   ║
  ║   ╚════██║██║██║  ╚██╗ ██╔╝██╔══╝  ██╔══██╗                   ║
  ║   ███████║██║███████╗╚████╔╝███████╗██║  ██║                  ║
  ║   ╚══════╝╚═╝╚══════╝ ╚═══╝ ╚══════╝╚═╝  ╚═╝                  ║
  ║                                                               ║
  ║   VPN Server v0.1.0                                           ║
  ║   Silver Ratio Cryptography from COINjecture                  ║
  ║                                                               ║
  ║   Created by: ADZ & Claude Opus 4.5                           ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
"#);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        // Just verify the Args struct is valid
        let args = Args::parse_from(&["silver-vpn-server", "--port", "8080"]);
        assert_eq!(args.port, 8080);
    }
}
