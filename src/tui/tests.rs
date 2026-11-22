use super::*;
use crate::aggregate::Limits;
use crate::testutil::*;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn screen(buffer: &Buffer) -> String {
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn shared_with_flow() -> Shared {
    let shared = Shared::new("eth0", Limits::default());
    shared.with_aggregator(|agg| agg.ingest(Pkt::out().at(100).observation(None)));
    shared
}

/// Runs the loop against `events`, one per call; `None` entries mean
/// "nothing arrived within the timeout". Returns the last frame drawn.
fn run_script(
    shared: &Shared,
    events: Vec<Option<Event>>,
    width: u16,
    height: u16,
) -> (io::Result<()>, String) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let mut events: VecDeque<_> = events.into();
    let result = event_loop(&mut terminal, shared, &Theme::color(), |_| {
        Ok(events.pop_front().expect("script ended without quitting"))
    });
    let last_frame = screen(terminal.backend().buffer());
    (result, last_frame)
}

#[test]
fn q_quits_and_the_ui_shows_the_flow_list_first() {
    let shared = shared_with_flow();
    let (result, frame) = run_script(&shared, vec![None, Some(key(KeyCode::Char('q')))], 120, 12);
    result.unwrap();
    assert!(frame.contains("10.0.0.2:50000"), "{frame}");
}

#[test]
fn ctrl_c_quits() {
    let shared = shared_with_flow();
    let ctrl_c = Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    let (result, _) = run_script(&shared, vec![Some(ctrl_c)], 120, 12);
    result.unwrap();
}

#[test]
fn a_requested_shutdown_ends_the_loop_without_input() {
    // This is how a SIGINT/SIGTERM from outside reaches the UI.
    let shared = shared_with_flow();
    shared.request_shutdown();
    let (result, _) = run_script(&shared, vec![], 120, 12);
    result.unwrap();
}

#[test]
fn shutdown_during_the_loop_is_noticed_between_polls() {
    let shared = shared_with_flow();
    let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
    let polls = AtomicUsize::new(0);
    let result = event_loop(&mut terminal, &shared, &Theme::color(), |_| {
        if polls.fetch_add(1, Ordering::SeqCst) == 2 {
            shared.request_shutdown();
        }
        assert!(polls.load(Ordering::SeqCst) < 10, "loop did not stop");
        Ok(None)
    });
    result.unwrap();
}

#[test]
fn input_errors_are_returned() {
    let shared = shared_with_flow();
    let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
    let result = event_loop(&mut terminal, &shared, &Theme::color(), |_| {
        Err(io::Error::other("tty gone"))
    });
    assert_eq!(result.unwrap_err().to_string(), "tty gone");
}

#[test]
fn enter_opens_details_and_resize_events_are_harmless() {
    let shared = shared_with_flow();
    let (result, frame) = run_script(
        &shared,
        vec![
            Some(key(KeyCode::Enter)),
            None,
            Some(Event::Resize(80, 24)),
            None,
            Some(key(KeyCode::Char('q'))),
        ],
        120,
        24,
    );
    result.unwrap();
    assert!(frame.contains("Local   10.0.0.2:50000"), "{frame}");
}

#[test]
fn display_refreshes_at_a_fixed_rate_not_per_packet() {
    let shared = shared_with_flow();
    let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
    let mut step = 0;
    let result = event_loop(&mut terminal, &shared, &Theme::color(), |_| {
        step += 1;
        match step {
            1 => {
                // Traffic arrives and the refresh interval elapses.
                shared.with_aggregator(|agg| {
                    agg.ingest(Pkt::out().udp().at(101).observation(None));
                });
                std::thread::sleep(REFRESH_INTERVAL + Duration::from_millis(20));
                Ok(None)
            }
            _ => Ok(Some(key(KeyCode::Char('q')))),
        }
    });
    result.unwrap();
    assert!(screen(terminal.backend().buffer()).contains("UDP"));
}

#[test]
fn paused_ui_keeps_showing_old_data_while_the_aggregator_advances() {
    let shared = shared_with_flow();
    let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
    let mut step = 0;
    let result = event_loop(&mut terminal, &shared, &Theme::color(), |_| {
        step += 1;
        match step {
            1 => Ok(Some(key(KeyCode::Char(' ')))),
            2 => Ok(None),
            3 => {
                shared.with_aggregator(|agg| {
                    agg.ingest(Pkt::out().udp().at(101).observation(None));
                });
                std::thread::sleep(REFRESH_INTERVAL + Duration::from_millis(20));
                Ok(None)
            }
            4 => Ok(Some(key(KeyCode::Char('q')))),
            _ => unreachable!(),
        }
    });
    result.unwrap();
    let frame = screen(terminal.backend().buffer());
    assert!(frame.contains("PAUSED"), "{frame}");
    assert!(!frame.contains("UDP"), "display must be frozen:\n{frame}");
    // The aggregator did not stop: the packet is accounted for.
    assert_eq!(shared.live().snapshot.counters.packets, 2);
}

#[test]
fn resuming_catches_up_at_once() {
    let shared = shared_with_flow();
    let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
    let mut step = 0;
    let result = event_loop(&mut terminal, &shared, &Theme::color(), |_| {
        step += 1;
        match step {
            1 => Ok(Some(key(KeyCode::Char(' ')))),
            2 => Ok(None),
            3 => {
                shared.with_aggregator(|agg| {
                    agg.ingest(Pkt::out().udp().at(101).observation(None));
                });
                Ok(Some(key(KeyCode::Char(' '))))
            }
            4 => Ok(None),
            5 => Ok(Some(key(KeyCode::Char('q')))),
            _ => unreachable!(),
        }
    });
    result.unwrap();
    let frame = screen(terminal.backend().buffer());
    assert!(!frame.contains("PAUSED"), "{frame}");
    assert!(frame.contains("UDP"), "{frame}");
}
