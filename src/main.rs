use anyhow::{Context, Result};
use clap::{command, Parser};
use lazy_static::lazy_static;
use prometheus::{register_gauge_with_registry, Gauge, Registry};
use prometheus_hyper::Server;
use regex::Regex;
use std::{
    net::{Ipv4Addr, SocketAddr},
    str::from_utf8,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
    sync::Notify,
    time::sleep,
};
use tracing::{debug, error, info, Level};
use tracing_subscriber::EnvFilter;

lazy_static! {
    static ref RE: Regex = Regex::new(r".*?:\s(-?\d+\.\d+)").unwrap();
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// Interface to bind
    #[arg(long, env = "EXPORTER_HOST", default_value = "0.0.0.0")]
    host: Ipv4Addr,
    /// Port to bind
    #[arg(long, env = "EXPORTER_PORT", default_value = "9978")]
    port: u16,
    /// Logging level
    #[arg(long, env = "EXPORTER_LOG", default_value = "info")]
    log_level: Level,
    /// Robot host
    #[arg(long, env = "PISUGAR_SERVER_HOST", default_value = "127.0.0.1")]
    pisugar_host: Ipv4Addr,
    /// Port to bind
    #[arg(long, env = "PISUGAR_SERVER_PORT", default_value = "8423")]
    pisugar_port: u16,
    /// Poll frequency in seconds
    #[arg(long, env = "PISUGAR_SERVER_POLL_FREQUENCY", default_value = "5")]
    poll_frequency: u64,
}
#[derive(Debug)]
struct BatteryStats {
    battery: f64,
    voltage: f64,
    current: f64,
}

fn parse(raw: &str) -> Result<f64> {
    let matched = RE
        .captures(raw)
        .and_then(|captures| captures.get(1))
        .context("No match")?;

    matched
        .as_str()
        .parse::<f64>()
        .with_context(|| format!("Broken output {}", matched.as_str()))
}

async fn fetch_stats<A: ToSocketAddrs>(host: A) -> Result<BatteryStats> {
    let mut buffer_battery_percent = [0; 14];
    let mut buffer_battery_voltage = [0; 16];
    let mut buffer_battery_current = [0; 16];
    {
        let mut socket = TcpStream::connect(&host).await?;
        socket.write_all(b"get battery").await?;
        socket.read_exact(&mut buffer_battery_percent).await?;
    }
    {
        let mut socket = TcpStream::connect(&host).await?;
        socket.write_all(b"get battery_i").await?;
        socket.read_exact(&mut buffer_battery_current).await?;
    }
    {
        let mut socket = TcpStream::connect(&host).await?;
        socket.write_all(b"get battery_v").await?;
        socket.read_exact(&mut buffer_battery_voltage).await?;
    }

    let battery = from_utf8(&buffer_battery_percent)
        .context("Malformed string")
        .and_then(parse)?;
    let voltage = from_utf8(&buffer_battery_voltage)
        .context("Malformed string")
        .and_then(parse)?;
    let current = from_utf8(&buffer_battery_current)
        .context("Malformed string")
        .and_then(parse)?;

    Ok(BatteryStats {
        battery,
        voltage,
        current,
    })
}

struct PiSugarMetrics {
    battery: Gauge,
    current: Gauge,
    voltage: Gauge,
}

impl PiSugarMetrics {
    fn new(registry: &Registry) -> Result<Self> {
        let battery = register_gauge_with_registry!("battery", "Battery level in percent", registry)?;
        let current = register_gauge_with_registry!("current", "Battery current in amps", registry)?;
        let voltage = register_gauge_with_registry!("voltage", "Battery voltage in volts", registry)?;

        Ok(Self {
            battery,
            current,
            voltage,
        })
    }
}

fn setup() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    setup();

    let config: Config = Config::parse();

    let registry = Arc::new(Registry::new_custom(Some("pisugar".into()), None)?);
    let metrics = PiSugarMetrics::new(&registry).expect("failed prometheus");

    let shutdown: Arc<Notify> = Default::default();
    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let address = format!("{}:{}", &config.host, &config.port);
        info!(%address, "Binding server");
        Server::run(
            Arc::clone(&registry),
            SocketAddr::from((config.host, config.port)),
            shutdown_clone.notified(),
        )
        .await
    });

    tokio::spawn(async move {
        match fetch_stats(SocketAddr::from((config.pisugar_host, config.pisugar_port))).await {
            Ok(stats) => {
                debug!(?stats, "Received battery stats");
                metrics.battery.set(stats.battery);
                metrics.voltage.set(stats.voltage);
                metrics.current.set(stats.current);
            }
            Err(error) => error!(%error, "Failed to update metrics"),
        };
        sleep(Duration::from_secs(config.poll_frequency)).await;
    });

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutting down");
            shutdown.notify_one();
        }
        Err(err) => {
            error!(%err, "Unable to listen for shutdown signal");
        }
    }
    Ok(())
}
