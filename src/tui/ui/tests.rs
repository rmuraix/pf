use super::*;
use crate::aggregate::Limits;
use crate::model::{EthernetSummary, MacAddress, NetEvent, Observation, UnparsedFrame};
use crate::pipeline::Shared;
use crate::testutil::*;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier};
use std::net::Ipv4Addr;
use std::sync::Arc;

fn feed(shared: &Shared, pkt: Pkt) {
    shared.with_aggregator(|agg| agg.ingest(pkt.observation(None)));
}

fn press(app: &mut App, code: KeyCode) {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn render(app: &mut App, theme: &Theme, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| draw(frame, app, theme)).unwrap();
    terminal.backend().buffer().clone()
}

fn text(buffer: &Buffer) -> String {
    let area = buffer.area;
    (0..area.height)
        .map(|y| {
            (0..area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_text(app: &mut App, width: u16, height: u16) -> String {
    text(&render(app, &Theme::color(), width, height))
}

/// Two TCP flows with traffic in both directions, plus one UDP flow.
fn populated() -> Shared {
    let shared = Shared::new("eth0", Limits::default());
    feed(&shared, Pkt::out().at(100).len(1500));
    feed(&shared, Pkt::inbound().at(101).len(66));
    feed(
        &shared,
        Pkt {
            dst: ("192.168.1.9", 8080),
            ..Pkt::out().at(102).len(300)
        },
    );
    feed(&shared, Pkt::out().udp().at(103).len(100));
    shared
}

fn event_shared() -> Shared {
    let shared = Shared::new("eth0", Limits::default());
    shared.with_aggregator(|agg| {
        agg.ingest(icmp(100));
        agg.ingest(Observation {
            timestamp: at(101),
            wire_len: 42,
            outcome: ParseOutcome::Event(NetEvent::new(
                "eth0",
                Direction::Inbound,
                ip(PEER),
                ip(HOST),
                Transport::Arp {
                    operation: 1,
                    sender_mac: MacAddress([1, 2, 3, 4, 5, 6]),
                    sender_ip: Ipv4Addr::new(1, 1, 1, 1),
                    target_mac: MacAddress([0; 6]),
                    target_ip: Ipv4Addr::new(10, 0, 0, 2),
                },
            )),
        });
        agg.ingest(Observation {
            timestamp: at(102),
            wire_len: 60,
            outcome: ParseOutcome::Unparsed(UnparsedFrame {
                interface: Arc::from("eth0"),
                length: 60,
                ethernet: Some(EthernetSummary {
                    source: MacAddress([0xaa; 6]),
                    destination: MacAddress([0xbb; 6]),
                    ethertype: 0x88cc,
                }),
                reason: UnparsedReason::UnsupportedEtherType,
            }),
        });
        agg.ingest(Observation {
            timestamp: at(103),
            wire_len: 54,
            outcome: ParseOutcome::Unparsed(UnparsedFrame {
                interface: Arc::from("eth0"),
                length: 54,
                ethernet: None,
                reason: UnparsedReason::Malformed("TCP"),
            }),
        });
    });
    shared
}

fn detail_app(shared: &Shared) -> App {
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Enter);
    let id = app.take_detail_request().unwrap();
    app.set_detail(id, shared.flow_detail(id));
    app
}

#[test]
fn flow_list_shows_endpoints_traffic_and_counters() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let screen = render_text(&mut app, 140, 14);

    for expected in [
        "PROTO",
        "LOCAL",
        "REMOTE",
        "← RECEIVED",
        "→ SENT",
        "PACKETS",
        "RATE",
        "LAST",
        "TCP",
        "UDP",
        "10.0.0.2:50000",
        "1.1.1.1:443",
        "192.168.1.9:8080",
        "1.5 KiB",
        "66 B",
        "1/1",
    ] {
        assert!(
            screen.contains(expected),
            "missing {expected:?} in:\n{screen}"
        );
    }
    assert!(screen.contains("Flows"));
    assert!(screen.contains("sort: activity"));
}

#[test]
fn status_bar_always_shows_interface_status_counters_and_keys() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let screen = render_text(&mut app, 100, 10);
    let status: Vec<&str> = screen.lines().rev().take(2).collect();
    let status = status.join("\n");

    for expected in [
        "eth0",
        "capturing",
        "packets 4",
        "flows 3",
        "lost 0",
        "quit",
        "pause",
        "filter",
        "sort",
        "open",
    ] {
        assert!(
            status.contains(expected),
            "missing {expected:?} in:\n{status}"
        );
    }
}

#[test]
fn paused_display_is_clearly_marked() {
    let shared = populated();
    let mut app = App::new(shared.live());
    assert!(!render_text(&mut app, 100, 10).contains("PAUSED"));
    press(&mut app, KeyCode::Char(' '));
    assert!(render_text(&mut app, 100, 10).contains("PAUSED"));
}

#[test]
fn packet_loss_and_evictions_are_reported_separately() {
    let shared = Shared::new(
        "eth0",
        Limits {
            max_flows: 8,
            event_capacity: 2,
            ..Limits::default()
        },
    );
    for port in 0..20 {
        feed(
            &shared,
            Pkt {
                src: (HOST, 1000 + port),
                ..Pkt::out()
            },
        );
    }
    for t in 0..5 {
        shared.with_aggregator(|agg| agg.ingest(icmp(100 + t)));
    }
    shared.set_dropped(7, 3);
    let mut app = App::new(shared.live());
    let screen = render_text(&mut app, 120, 10);
    let status = screen.lines().rev().nth(1).unwrap().to_owned();

    assert!(status.contains("lost 10"), "{status}");
    assert!(status.contains("evicted: 12 flows, 3 events"), "{status}");
}

#[test]
fn capture_failure_is_visible() {
    let shared = populated();
    shared.fail("interface went down");
    let mut app = App::new(shared.live());
    let screen = render_text(&mut app, 100, 10);
    assert!(screen.contains("failed: interface went down"), "{screen}");
}

#[test]
fn filter_is_shown_in_the_top_bar_and_prompt() {
    let shared = populated();
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Char('/'));
    for c in "udp".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    let screen = render_text(&mut app, 100, 10);
    assert!(screen.contains("/ udp"), "{screen}");
    assert!(screen.contains("flows 1/3"), "{screen}");
    assert!(!screen.contains("8080"));

    press(&mut app, KeyCode::Enter);
    let screen = render_text(&mut app, 100, 10);
    assert!(screen.contains("filter: udp"), "{screen}");
}

#[test]
fn selected_row_is_highlighted_and_follows_navigation() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let theme = Theme::color();

    let reversed_rows = |buffer: &Buffer| -> Vec<u16> {
        (0..buffer.area.height)
            .filter(|&y| buffer[(20, y)].modifier.contains(Modifier::REVERSED))
            .collect()
    };
    let first = reversed_rows(&render(&mut app, &theme, 140, 14));
    assert_eq!(first, [2], "first data row is highlighted");
    press(&mut app, KeyCode::Down);
    let second = reversed_rows(&render(&mut app, &theme, 140, 14));
    assert_eq!(second, [3]);
}

#[test]
fn only_the_visible_window_follows_the_selection_in_long_lists() {
    let shared = Shared::new("eth0", Limits::default());
    for port in 0..200u16 {
        feed(
            &shared,
            Pkt {
                src: (HOST, 10_000 + port),
                ..Pkt::out().at(100 + u64::from(port))
            },
        );
    }
    let mut app = App::new(shared.live());
    let theme = Theme::color();
    render(&mut app, &theme, 140, 16);
    for _ in 0..150 {
        press(&mut app, KeyCode::Down);
    }
    let screen = text(&render(&mut app, &theme, 140, 16));
    // Newest first: row 150 is port 10_000 + (199 - 150) = 10_049.
    assert!(screen.contains("10.0.0.2:10049"), "{screen}");
    assert!(!screen.contains("10.0.0.2:10199"));
}

#[test]
fn narrow_terminals_drop_optional_columns_first() {
    let shared = populated();
    let mut app = App::new(shared.live());
    for (width, kept, dropped) in [
        (140, "RATE", ""),
        (100, "← RECEIVED", "RATE"),
        (70, "LAST SEEN", "PACKETS"),
        (60, "REMOTE", "RECEIVED"),
    ] {
        let screen = render_text(&mut app, width, 10);
        assert!(screen.contains(kept), "{width}: missing {kept}:\n{screen}");
        if !dropped.is_empty() {
            assert!(
                !screen.contains(dropped),
                "{width}: unexpected {dropped}:\n{screen}"
            );
        }
    }
}

#[test]
fn event_log_shows_non_flow_packets_and_parse_errors() {
    let shared = event_shared();
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Tab);
    let screen = render_text(&mut app, 130, 12);

    for expected in [
        "Events",
        "TIME (UTC)",
        "PROTO",
        "ENDPOINTS",
        "INFO",
        "00:01:43.000", // 103 s after the epoch
        "ICMP",
        "echo request seq=1 id=2",
        "10.0.0.2 → 1.1.1.1",
        "ARP",
        "who-has 10.0.0.2 tell 1.1.1.1",
        "unsupported EtherType 0x88cc",
        "aa:aa:aa:aa:aa:aa → bb:bb:bb:bb:bb:bb",
        "malformed TCP header",
        "98 B",
    ] {
        assert!(
            screen.contains(expected),
            "missing {expected:?} in:\n{screen}"
        );
    }
    // Newest first.
    let malformed = screen.find("malformed TCP").unwrap();
    let icmp = screen.find("echo request").unwrap();
    assert!(malformed < icmp);
}

#[test]
fn event_log_placeholder_when_empty() {
    let shared = populated();
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    assert!(render_text(&mut app, 100, 10).contains("no ICMP, ARP or unparsed packets"));
}

#[test]
fn detail_view_separates_directions_and_lists_history() {
    let shared = populated();
    feed(&shared, Pkt::out().at(104).len(1500));
    let mut app = detail_app(&shared);
    let screen = render_text(&mut app, 120, 24);

    for expected in [
        "Details",
        "TCP",
        "interface eth0",
        "state open",
        "Local   10.0.0.2:50000",
        "Remote  1.1.1.1:443",
        "← IN",
        "→ OUT",
        "packets 1 ",
        "packets 2 ",
        "bytes 66 B",
        "bytes 2.9 KiB",
        "Total   packets 3",
        "Active",
        "Recent packets: last 3 of 3",
        "+0.000s",
        "+1.000s",
        "+4.000s",
        "TCP FLAGS",
        "ACK",
    ] {
        assert!(
            screen.contains(expected),
            "missing {expected:?} in:\n{screen}"
        );
    }
}

#[test]
fn detail_view_says_when_the_flow_has_ended() {
    let shared = populated();
    let mut app = detail_app(&shared);
    shared.with_aggregator(|agg| agg.expire(at(100_000)));
    app.apply(shared.live());
    let id = app.take_detail_request().unwrap();
    app.set_detail(id, shared.flow_detail(id));
    let screen = render_text(&mut app, 120, 24);
    assert!(screen.contains("ended (expired or evicted)"), "{screen}");
    assert!(screen.contains("Recent packets"));
}

#[test]
fn detail_history_scrolls_towards_older_packets() {
    let shared = Shared::new("eth0", Limits::default());
    for t in 0..30u64 {
        feed(&shared, Pkt::out().at(100 + t).len(1000 + t as usize));
    }
    let mut app = detail_app(&shared);
    // 11 rows for history at this height.
    let newest = render_text(&mut app, 100, 21);
    assert!(
        newest.contains("1029 B") && !newest.contains("1018 B"),
        "{newest}"
    );
    for _ in 0..10 {
        press(&mut app, KeyCode::Up);
    }
    let older = render_text(&mut app, 100, 21);
    assert!(older.contains("scrolled back 10"), "{older}");
    assert!(
        !older.contains("1029 B") && older.contains("1019 B"),
        "{older}"
    );
}

#[test]
fn monochrome_theme_uses_no_colours() {
    let shared = populated();
    let theme = Theme::monochrome();
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('/'));
    for view_keys in [
        vec![],
        vec![KeyCode::Enter],
        vec![KeyCode::Esc, KeyCode::Tab, KeyCode::Tab],
    ] {
        app.editing_filter = false;
        for key in view_keys {
            press(&mut app, key);
            if let Some(id) = app.take_detail_request() {
                app.set_detail(id, shared.flow_detail(id));
            }
        }
        let buffer = render(&mut app, &theme, 120, 20);
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                assert_eq!(
                    (cell.fg, cell.bg),
                    (Color::Reset, Color::Reset),
                    "({x},{y}) in {:?}",
                    app.view
                );
            }
        }
    }
    let shared = event_shared();
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Tab);
    let buffer = render(&mut app, &theme, 120, 20);
    assert!(
        buffer
            .content
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
    );
}

#[test]
fn monochrome_direction_is_still_readable() {
    let shared = populated();
    let theme = Theme::monochrome();
    let mut app = detail_app(&shared);
    let screen = text(&render(&mut app, &theme, 120, 20));
    assert!(screen.contains("← IN") && screen.contains("→ OUT"));
}

#[test]
fn color_theme_does_use_colours() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let buffer = render(&mut app, &Theme::color(), 140, 10);
    assert!(buffer.content.iter().any(|c| c.fg == Color::LightGreen));
    assert!(buffer.content.iter().any(|c| c.fg == Color::LightMagenta));
}

#[test]
fn tiny_terminals_do_not_panic() {
    let flows = populated();
    let events = event_shared();
    for (shared, label) in [(&flows, "flows"), (&events, "events")] {
        for width in [0, 1, 5, 20, 39, 40, 41, 60, 80, 200] {
            for height in [0, 1, 2, 3, 5, 6, 7, 8, 30] {
                for view in 0..3 {
                    let mut app = App::new(shared.live());
                    match view {
                        1 => {
                            press(&mut app, KeyCode::Enter);
                            if let Some(id) = app.take_detail_request() {
                                app.set_detail(id, shared.flow_detail(id));
                            }
                        }
                        2 => press(&mut app, KeyCode::Tab),
                        _ => {}
                    }
                    let _ = (label, render(&mut app, &Theme::color(), width, height));
                    app.editing_filter = true;
                    let _ = render(&mut app, &Theme::monochrome(), width, height);
                }
            }
        }
    }
}

#[test]
fn too_small_terminals_get_a_message() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let screen = render_text(&mut app, 30, 8);
    assert!(screen.contains("too small"), "{screen}");
    assert!(!render_text(&mut app, 40, 6).contains("too small"));
}

#[test]
fn smallest_supported_size_still_has_status_and_data() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let screen = render_text(&mut app, MIN_WIDTH, MIN_HEIGHT);
    assert!(screen.contains("eth0"));
    assert!(screen.contains("10.0.0.2"));
    assert!(screen.contains("quit"));
}

#[test]
fn resizing_between_frames_is_handled() {
    let shared = populated();
    let mut app = App::new(shared.live());
    let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
    for (w, h) in [(120, 20), (30, 5), (200, 50), (40, 6), (120, 20)] {
        terminal.backend_mut().resize(w, h);
        terminal
            .draw(|frame| draw(frame, &mut app, &Theme::color()))
            .unwrap();
    }
    assert!(text(terminal.backend().buffer()).contains("10.0.0.2:50000"));
}

#[test]
fn scroll_window_keeps_the_selection_visible() {
    let mut offset = 0;
    assert_eq!(scroll_window(&mut offset, Some(0), 5, 20), 0..5);
    assert_eq!(scroll_window(&mut offset, Some(7), 5, 20), 3..8);
    assert_eq!(scroll_window(&mut offset, Some(4), 5, 20), 3..8);
    assert_eq!(scroll_window(&mut offset, Some(2), 5, 20), 2..7);
    // The list shrank: no blank space is left at the end.
    assert_eq!(scroll_window(&mut offset, Some(1), 5, 6), 1..6);
    assert_eq!(scroll_window(&mut offset, None, 5, 3), 0..3);
    assert_eq!(scroll_window(&mut offset, Some(0), 0, 3), 0..0);
    assert_eq!(scroll_window(&mut offset, None, 5, 0), 0..0);
}

#[test]
fn icmpv6_and_arp_replies_are_described() {
    let event = |transport| {
        describe_net_event(&NetEvent::new(
            "eth0",
            Direction::Outbound,
            ip("fe80::1"),
            ip("ff02::1"),
            transport,
        ))
    };
    assert_eq!(
        event(Transport::Icmpv6 { type_u8: 135 }).info,
        "neighbor solicitation (type 135)"
    );
    assert_eq!(event(Transport::Icmpv6 { type_u8: 200 }).info, "type 200");
    let reply = event(Transport::Arp {
        operation: 2,
        sender_mac: MacAddress([1, 2, 3, 4, 5, 6]),
        sender_ip: Ipv4Addr::new(10, 0, 0, 1),
        target_mac: MacAddress([0; 6]),
        target_ip: Ipv4Addr::new(10, 0, 0, 2),
    });
    assert_eq!(reply.info, "10.0.0.1 is-at 01:02:03:04:05:06");
    assert_eq!(reply.protocol, "ARP");
}

#[test]
fn tcp_flags_text_lists_set_flags() {
    let flags = TcpFlags {
        syn: true,
        ack: true,
        fin: false,
        rst: false,
    };
    assert_eq!(tcp_flags_text(Some(flags)), "SYN ACK");
    assert_eq!(tcp_flags_text(Some(TcpFlags::default())), "-");
    assert_eq!(tcp_flags_text(None), "-");
}
