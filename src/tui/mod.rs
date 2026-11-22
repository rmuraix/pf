//! Interactive terminal UI.
//!
//! * `app`: state and key handling (no I/O)
//! * `ui`: drawing
//! * `filter`, `format`, `theme`: helpers
//!
//! The UI never blocks the workers: it copies a snapshot out of
//! [`Shared`] at a fixed rate, and in between only reacts to input.

mod app;
mod filter;
mod format;
mod theme;
mod ui;

use std::io::{self, Stdout, stdout};
use std::panic;
use std::thread;
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

use crate::pipeline::Shared;

pub use app::App;
pub use theme::Theme;

/// How often the displayed data is refreshed from the aggregator.
const REFRESH_INTERVAL: Duration = Duration::from_millis(100);

/// Leaves raw mode and the alternate screen and shows the cursor. Every step
/// is attempted even if an earlier one fails, and doing it twice is harmless.
fn restore_terminal() -> io::Result<()> {
    let raw_mode = disable_raw_mode();
    let screen = execute!(stdout(), LeaveAlternateScreen, Show);
    raw_mode.and(screen)
}

/// Owns the terminal for the lifetime of the UI. Dropping it restores the
/// terminal on every exit path: normal return, `?`, and unwinding.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        install_panic_hook();
        enable_raw_mode()?;
        let terminal = execute!(stdout(), EnterAlternateScreen)
            .and_then(|()| Terminal::new(CrosstermBackend::new(stdout())));
        match terminal {
            Ok(terminal) => Ok(Self { terminal }),
            Err(err) => {
                let _ = restore_terminal();
                Err(err)
            }
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Err(err) = restore_terminal() {
            eprintln!("pf: failed to restore the terminal: {err}");
        }
    }
}

/// Restores the terminal before the default hook prints a panic of the UI
/// thread, so the message is not lost in the alternate screen. Panics of
/// worker threads are caught there and shown in the status bar; printing
/// them would only corrupt the display.
fn install_panic_hook() {
    let ui_thread = thread::current().id();
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui_thread {
            let _ = restore_terminal();
            previous(info);
        }
    }));
}

/// Runs the UI until the user quits or a shutdown is requested.
pub fn run(shared: &Shared, theme: &Theme) -> io::Result<()> {
    let mut guard = TerminalGuard::enter()?;
    event_loop(&mut guard.terminal, shared, theme, read_event)
}

fn read_event(timeout: Duration) -> io::Result<Option<Event>> {
    if event::poll(timeout)? {
        event::read().map(Some)
    } else {
        Ok(None)
    }
}

/// The UI loop, with the input source injected so tests can script it.
/// `next_event(timeout)` waits up to `timeout` for one event.
fn event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    shared: &Shared,
    theme: &Theme,
    mut next_event: impl FnMut(Duration) -> io::Result<Option<Event>>,
) -> io::Result<()> {
    let mut app = App::new(shared.live());
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
    loop {
        if app.should_quit() || shared.shutdown_requested() {
            return Ok(());
        }
        let resumed = app.take_refresh_request();
        let due = Instant::now() >= next_refresh;
        if due {
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
        // While paused the snapshot is not even taken; the workers keep
        // counting regardless.
        if resumed || (due && !app.paused) {
            app.apply(shared.live());
        }
        if let Some(id) = app.take_detail_request() {
            app.set_detail(id, shared.flow_detail(id));
        }
        terminal.draw(|frame| ui::draw(frame, &mut app, theme))?;

        // Input is handled as soon as it arrives; only the data refresh is
        // rate limited.
        let mut event = next_event(next_refresh.saturating_duration_since(Instant::now()))?;
        while let Some(current) = event {
            if let Event::Key(key) = current {
                app.handle_key(key);
            }
            event = if app.should_quit() {
                None
            } else {
                next_event(Duration::ZERO)?
            };
        }
    }
}

#[cfg(test)]
mod tests;
