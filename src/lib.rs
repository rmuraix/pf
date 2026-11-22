//! Pipeline: `capture` → `CapturedFrame` → `parser` → `Observation` →
//! `aggregate` (flows, event log) → `tui`. `pipeline` runs the first stages
//! on worker threads; the UI only reads snapshots of the aggregated state.
//! Only `capture` uses `pcap` types and only `parser` uses `etherparse` types.

use std::io::IsTerminal;

pub mod aggregate;
pub mod capture;
pub mod flow;
pub mod frame;
pub mod model;
pub mod parser;
pub mod pipeline;
pub mod tui;

#[cfg(test)]
mod testutil;

/// Runtime configuration passed from the CLI layer.
pub struct Config {
    pub interface: String,
    pub noudp: bool,
    pub no_color: bool,
}

/// `NO_COLOR` counts when set to a non-empty value (<https://no-color.org>).
fn color_disabled(config: &Config) -> bool {
    config.no_color || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// Opens the capture and runs the UI until the user quits. Returns an error
/// instead of panicking; the terminal is restored before it is returned.
pub fn run(config: Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "pf is an interactive TUI and needs a terminal: stdin and stdout must not be piped or redirected"
    );

    // Opened before the UI starts so that errors (unknown interface, missing
    // privileges) are printed as plain text.
    let cap = capture::Capture::open(&config.interface)?;
    let parser = parser::Parser::new(cap.host_ips().into_iter().collect(), config.noudp);
    let pipeline = pipeline::Pipeline::spawn(cap, parser, aggregate::Limits::default())?;

    // Raw mode turns Ctrl+C into a key event the UI handles itself; this is
    // for signals sent from outside (kill, a closing terminal).
    let stopper = pipeline.stopper();
    if let Err(err) = ctrlc::set_handler(move || stopper.stop()) {
        let _ = pipeline.shutdown();
        return Err(err.into());
    }

    let theme = tui::Theme::new(!color_disabled(&config));
    let ui = tui::run(pipeline.shared(), &theme);
    // The terminal is already restored here, so a capture error prints cleanly.
    let capture = pipeline.shutdown();
    ui?;
    capture
}
