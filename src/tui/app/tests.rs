use super::*;
use crate::aggregate::Limits;
use crate::pipeline::Shared;
use crate::testutil::*;
use ratatui::crossterm::event::KeyEventKind;

fn shared() -> Shared {
    Shared::new("eth0", Limits::default())
}

fn feed(shared: &Shared, pkt: Pkt) {
    shared.with_aggregator(|agg| agg.ingest(pkt.observation(None)));
}

/// A flow on source port `port`, last active at `time`.
fn flow_pkt(port: u16, time: u64, wire_len: usize) -> Pkt {
    Pkt {
        src: (HOST, port),
        ..Pkt::out().at(time).len(wire_len)
    }
}

fn press(app: &mut App, code: KeyCode) {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

fn selected_port(app: &App) -> u16 {
    let index = app.flow_selection.index().unwrap();
    app.data.snapshot.flows[app.flow_rows[index]].local.port()
}

fn visible_ports(app: &App) -> Vec<u16> {
    app.flow_rows
        .iter()
        .map(|&i| app.data.snapshot.flows[i].local.port())
        .collect()
}

/// Three flows, ports 1001..=1003, most recent first: 1003, 1002, 1001.
fn app_with_flows() -> (Shared, App) {
    let shared = shared();
    for (i, port) in [1001, 1002, 1003].into_iter().enumerate() {
        feed(&shared, flow_pkt(port, 100 + i as u64, 100 * (4 - i)));
    }
    let app = App::new(shared.live());
    (shared, app)
}

#[test]
fn flows_start_sorted_by_activity_with_the_first_row_selected() {
    let (_, app) = app_with_flows();
    assert_eq!(visible_ports(&app), [1003, 1002, 1001]);
    assert_eq!(app.flow_selection.index(), Some(0));
}

#[test]
fn arrows_and_vi_keys_navigate_and_clamp() {
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Char('j'));
    assert_eq!(selected_port(&app), 1002);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_port(&app), 1001, "clamped at the last row");
    press(&mut app, KeyCode::Char('k'));
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Up);
    assert_eq!(selected_port(&app), 1003, "clamped at the first row");
    press(&mut app, KeyCode::PageDown);
    assert_eq!(selected_port(&app), 1001);
}

#[test]
fn selection_follows_the_flow_when_the_order_changes() {
    let (shared, mut app) = app_with_flows();
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_port(&app), 1001);

    // 1001 becomes the most recently active flow and moves to the top.
    feed(&shared, flow_pkt(1001, 110, 10));
    app.apply(shared.live());

    assert_eq!(visible_ports(&app), [1001, 1003, 1002]);
    assert_eq!(selected_port(&app), 1001);
    assert_eq!(app.flow_selection.index(), Some(0));
}

#[test]
fn selection_stays_on_the_same_row_when_its_flow_disappears() {
    let shared = shared();
    for (i, port) in [1001, 1002, 1003].into_iter().enumerate() {
        feed(&shared, flow_pkt(port, 100 + 10 * i as u64, 100));
    }
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Down); // 1002
    shared.with_aggregator(|agg| agg.expire(at(1000)));
    feed(&shared, flow_pkt(2000, 1000, 100));
    feed(&shared, flow_pkt(2001, 1001, 100));
    app.apply(shared.live());

    assert_eq!(visible_ports(&app), [2001, 2000]);
    assert_eq!(
        app.flow_selection.index(),
        Some(1),
        "same position, clamped"
    );
}

#[test]
fn selection_is_empty_without_flows() {
    let app = App::new(shared().live());
    assert_eq!(app.flow_selection.index(), None);
}

#[test]
fn enter_opens_the_selected_flow_and_esc_returns() {
    let (shared, mut app) = app_with_flows();
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.view, View::Detail);
    let id = app.take_detail_request().expect("details requested");
    app.set_detail(id, shared.flow_detail(id));
    assert_eq!(
        app.detail.as_ref().unwrap().detail.summary.local.port(),
        1002
    );

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.view, View::Flows);
}

#[test]
fn enter_without_flows_does_nothing() {
    let mut app = App::new(shared().live());
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.view, View::Flows);
    assert!(app.take_detail_request().is_none());
}

#[test]
fn tab_cycles_through_the_views_skipping_details_without_a_flow() {
    let mut app = App::new(shared().live());
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view, View::Events);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view, View::Flows);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.view, View::Events);

    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view, View::Detail);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view, View::Events);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view, View::Flows);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.view, View::Flows, "Esc in the root view stays put");
}

#[test]
fn esc_leaves_the_event_log() {
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view, View::Events);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.view, View::Flows);
}

#[test]
fn sort_cycles_between_activity_and_traffic() {
    let (_, mut app) = app_with_flows();
    // Bytes: 1001 → 400, 1002 → 300, 1003 → 200.
    assert_eq!(visible_ports(&app), [1003, 1002, 1001]);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.sort, SortKey::Traffic);
    assert_eq!(visible_ports(&app), [1001, 1002, 1003]);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.sort, SortKey::Activity);
    assert_eq!(visible_ports(&app), [1003, 1002, 1001]);
}

#[test]
fn sort_key_only_applies_to_the_flow_list() {
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.sort, SortKey::Activity);
}

#[test]
fn filter_narrows_the_flow_list_while_typing() {
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Char('/'));
    assert!(app.editing_filter);
    type_text(&mut app, "1002");
    assert_eq!(visible_ports(&app), [1002]);
    press(&mut app, KeyCode::Backspace);
    type_text(&mut app, "3");
    assert_eq!(visible_ports(&app), [1003]);
    press(&mut app, KeyCode::Enter);
    assert!(!app.editing_filter);
    assert_eq!(app.filter_text, "1003");
    assert_eq!(visible_ports(&app), [1003], "filter stays applied");
}

#[test]
fn typing_in_the_filter_does_not_trigger_shortcuts() {
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "q j s k tcp");
    assert!(!app.should_quit());
    assert_eq!(app.sort, SortKey::Activity);
    assert_eq!(app.filter_text, "q j s k tcp");
    assert!(!app.paused);
    press(&mut app, KeyCode::Char(' '));
    assert!(!app.paused, "space is part of the filter text");
}

#[test]
fn esc_clears_the_filter_while_editing_and_afterwards() {
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "1002");
    press(&mut app, KeyCode::Esc);
    assert!(!app.editing_filter);
    assert_eq!(app.filter_text, "");
    assert_eq!(visible_ports(&app).len(), 3);

    press(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "udp");
    press(&mut app, KeyCode::Enter);
    assert!(visible_ports(&app).is_empty());
    press(&mut app, KeyCode::Esc);
    assert_eq!(visible_ports(&app).len(), 3, "Esc clears an applied filter");
}

#[test]
fn filter_applies_to_the_event_log() {
    let shared = shared();
    feed(&shared, flow_pkt(1001, 100, 100));
    shared.with_aggregator(|agg| agg.ingest(icmp(101)));
    let mut app = App::new(shared.live());
    assert_eq!(app.event_rows.len(), 1);

    press(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "arp");
    assert!(app.event_rows.is_empty());
    for _ in 0.."arp".len() {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "icmp");
    assert_eq!(app.event_rows.len(), 1);
}

#[test]
fn quit_keys() {
    let mut app = App::new(shared().live());
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit());

    let mut app = App::new(shared().live());
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.should_quit());
}

#[test]
fn ctrl_c_quits_even_while_editing_the_filter() {
    let mut app = App::new(shared().live());
    press(&mut app, KeyCode::Char('/'));
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.should_quit());
}

#[test]
fn other_ctrl_chords_are_not_shortcuts() {
    let mut app = App::new(shared().live());
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::ALT));
    assert!(!app.should_quit());
    assert!(!app.paused);
}

#[test]
fn key_releases_are_ignored() {
    // Windows reports releases as well as presses.
    let mut app = App::new(shared().live());
    let mut release = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
    release.kind = KeyEventKind::Release;
    app.handle_key(release);
    assert!(!app.should_quit());
}

#[test]
fn pause_freezes_the_display_but_not_the_counters() {
    let (shared, mut app) = app_with_flows();
    let packets_before = app.data.snapshot.counters.packets;
    press(&mut app, KeyCode::Char(' '));
    assert!(app.paused);
    assert!(!app.take_refresh_request());

    // Traffic keeps arriving and is aggregated while the display is paused.
    for _ in 0..50 {
        feed(&shared, flow_pkt(1001, 110, 100));
    }
    feed(&shared, flow_pkt(4000, 110, 100));
    app.apply(shared.live());

    assert_eq!(app.data.snapshot.counters.packets, packets_before);
    assert_eq!(visible_ports(&app), [1003, 1002, 1001]);
    // Navigation still works on the frozen data.
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_port(&app), 1002);

    press(&mut app, KeyCode::Char(' '));
    assert!(!app.paused);
    assert!(
        app.take_refresh_request(),
        "resuming catches up immediately"
    );
    app.apply(shared.live());
    assert_eq!(app.data.snapshot.counters.packets, packets_before + 51);
    assert_eq!(app.data.snapshot.flows.len(), 4);
    let flow = app
        .data
        .snapshot
        .flows
        .iter()
        .find(|f| f.local.port() == 1001)
        .unwrap();
    assert_eq!(flow.packets.outbound, 51, "no packet was lost while paused");
}

#[test]
fn detail_of_an_expired_flow_keeps_its_last_state_and_is_marked_ended() {
    let (shared, mut app) = app_with_flows();
    press(&mut app, KeyCode::Enter);
    let id = app.take_detail_request().unwrap();
    app.set_detail(id, shared.flow_detail(id));
    assert!(!app.detail.as_ref().unwrap().ended);

    shared.with_aggregator(|agg| agg.expire(at(100_000)));
    app.apply(shared.live());
    let id = app.take_detail_request().expect("refresh requests details");
    app.set_detail(id, shared.flow_detail(id));

    let state = app.detail.as_ref().unwrap();
    assert!(state.ended);
    assert_eq!(state.detail.summary.packets.outbound, 1);
}

#[test]
fn detail_falls_back_to_the_listed_summary_when_the_flow_is_already_gone() {
    // Opened from a paused (stale) list after the flow has expired.
    let (_, mut app) = app_with_flows();
    press(&mut app, KeyCode::Enter);
    let id = app.take_detail_request().unwrap();
    app.set_detail(id, None);
    let state = app.detail.as_ref().unwrap();
    assert!(state.ended);
    assert!(state.detail.history.is_empty());
}

#[test]
fn history_scroll_is_clamped_to_the_available_packets() {
    let shared = shared();
    for t in 0..5 {
        feed(&shared, flow_pkt(1001, 100 + t, 100));
    }
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Enter);
    let id = app.take_detail_request().unwrap();
    app.set_detail(id, shared.flow_detail(id));

    for _ in 0..20 {
        press(&mut app, KeyCode::Up);
    }
    assert_eq!(app.detail.as_ref().unwrap().scroll, 4);
    for _ in 0..20 {
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(app.detail.as_ref().unwrap().scroll, 0);
}

#[test]
fn event_selection_follows_the_entry_as_new_events_arrive() {
    let shared = shared();
    shared.with_aggregator(|agg| agg.ingest(icmp(100)));
    shared.with_aggregator(|agg| agg.ingest(icmp(101)));
    let mut app = App::new(shared.live());
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Down); // older of the two
    let seq = app.data.snapshot.events[app.event_rows[app.event_selection.index().unwrap()]].seq;
    assert_eq!(seq, 1);

    shared.with_aggregator(|agg| agg.ingest(icmp(102)));
    app.apply(shared.live());
    let index = app.event_selection.index().unwrap();
    assert_eq!(index, 2);
    assert_eq!(app.data.snapshot.events[app.event_rows[index]].seq, 1);
}

#[test]
fn details_are_only_refreshed_while_the_details_view_is_open() {
    let (shared, mut app) = app_with_flows();
    press(&mut app, KeyCode::Enter);
    let id = app.take_detail_request().unwrap();
    app.set_detail(id, shared.flow_detail(id));

    app.apply(shared.live());
    assert_eq!(app.take_detail_request(), Some(id));

    press(&mut app, KeyCode::Esc);
    app.apply(shared.live());
    assert_eq!(app.take_detail_request(), None);
}
