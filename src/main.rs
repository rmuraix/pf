use clap::Parser;
use std::process::ExitCode;

/// Interactive network flow monitor.
///
/// Captures on the given interface and groups TCP/UDP traffic into
/// bidirectional flows. Needs a terminal and capture privileges (see the
/// README). Press `q` or Ctrl+C to quit; keys are listed in the status bar.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Name of the network interface
    #[arg(short, long, value_name = "NETWORK INTERFACE")]
    interface: String,
    /// Ignore UDP: no UDP flows, and UDP packets are not counted
    #[arg(long)]
    noudp: bool,
    /// Use a monochrome theme (or set NO_COLOR)
    #[arg(long = "no-color")]
    no_color: bool,
}

fn main() -> ExitCode {
    let cli: Cli = Cli::parse();
    let config = pf::Config {
        interface: cli.interface,
        noudp: cli.noudp,
        no_color: cli.no_color,
    };
    if let Err(err) = pf::run(config) {
        eprintln!("pf error: {:#}", err);
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
