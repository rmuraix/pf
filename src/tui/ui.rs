//! Drawing. Reads [`App`] and renders it; the only state it writes back is
//! the scroll offset of each table.

use std::ops::Range;
use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use crate::aggregate::EventEntry;
use crate::flow::{FlowDetail, FlowSummary, PacketSample};
use crate::model::{
    Direction, IcmpKind, NetEvent, ParseOutcome, TcpFlags, Transport, UnparsedFrame, UnparsedReason,
};
use crate::pipeline::{CaptureInfo, CaptureStatus};

use super::app::{App, DetailState, View};
use super::format;
use super::theme::Theme;

/// Below this the layout cannot show anything useful.
pub const MIN_WIDTH: u16 = 40;
pub const MIN_HEIGHT: u16 = 6;

const SEPARATOR: &str = " │ ";
const IN_ARROW: &str = "←";
const OUT_ARROW: &str = "→";

pub fn draw(frame: &mut Frame, app: &mut App, theme: &Theme) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let message = format!(
            "pf: terminal too small ({}x{}), need at least {MIN_WIDTH}x{MIN_HEIGHT}",
            area.width, area.height
        );
        frame.render_widget(Paragraph::new(message).wrap(Wrap { trim: true }), area);
        return;
    }
    let [top, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(area);

    draw_top_bar(frame, top, app, theme);
    match app.view {
        View::Flows => draw_flows(frame, body, app, theme),
        View::Events => draw_events(frame, body, app, theme),
        View::Detail => draw_detail(frame, body, app, theme),
    }
    draw_status(frame, status, app, theme);
}

fn direction_span(direction: Direction, theme: &Theme) -> Span<'static> {
    match direction {
        Direction::Inbound => Span::styled(format!("{IN_ARROW} IN "), theme.inbound),
        Direction::Outbound => Span::styled(format!("{OUT_ARROW} OUT"), theme.outbound),
    }
}

/// Keeps `selected` inside a window of `visible` rows over `len` rows and
/// returns the range to draw. Only those rows are turned into cells, so the
/// cost of a frame does not grow with the number of flows.
fn scroll_window(
    offset: &mut usize,
    selected: Option<usize>,
    visible: usize,
    len: usize,
) -> Range<usize> {
    if visible == 0 || len == 0 {
        *offset = 0;
        return 0..0;
    }
    if let Some(selected) = selected {
        if selected < *offset {
            *offset = selected;
        } else if selected >= *offset + visible {
            *offset = selected + 1 - visible;
        }
    }
    *offset = (*offset).min(len.saturating_sub(visible));
    *offset..(*offset + visible).min(len)
}

fn header_row<'a>(labels: impl IntoIterator<Item = &'a str>, theme: &Theme) -> Row<'a> {
    Row::new(labels.into_iter().map(Cell::from)).style(theme.header)
}

// --- top and status bars -------------------------------------------------

fn draw_top_bar(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let mut tabs = Vec::new();
    for view in View::ALL {
        let style = if view == app.view {
            theme.tab_active
        } else {
            theme.dim
        };
        tabs.push(Span::styled(format!(" {} ", view.title()), style));
    }
    let mut info = vec![Span::raw(format!("sort: {}", app.sort.label()))];
    if !app.filter_text.is_empty() {
        info.push(Span::raw(format!("  filter: {}", app.filter_text)));
    }
    let info = Line::from(info);
    let info_width = (info.width() as u16 + 1).min(area.width / 2);
    let [left, right] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(info_width)]).areas(area);
    frame.render_widget(Line::from(tabs), left);
    if app.view == View::Flows {
        frame.render_widget(info.alignment(Alignment::Right), right);
    }
}

/// Joins `segments` with separators, skipping any that no longer fit. Earlier
/// segments are more important.
fn fit<'a>(segments: Vec<Vec<Span<'a>>>, width: usize, theme: &Theme) -> Line<'a> {
    let mut spans = Vec::new();
    let mut used = 0;
    for segment in segments {
        let segment_width: usize = segment.iter().map(Span::width).sum();
        let needed = segment_width
            + if used > 0 {
                SEPARATOR.chars().count()
            } else {
                0
            };
        if used + needed > width {
            continue;
        }
        if used > 0 {
            spans.push(Span::styled(SEPARATOR, theme.dim));
        }
        spans.extend(segment);
        used += needed;
    }
    Line::from(spans)
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let [stats, keys] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let width = usize::from(area.width);

    frame.render_widget(fit(stats_segments(app, theme), width, theme), stats);

    if app.editing_filter {
        let prompt = format!("/ {}", app.filter_text);
        let hint = "  Enter: apply  Esc: clear  (tcp udp icmp arp, port, ip)";
        frame.render_widget(
            Line::from(vec![
                Span::styled(prompt.clone(), theme.header),
                Span::styled(hint, theme.dim),
            ]),
            keys,
        );
        let cursor_x =
            area.x + (Line::from(prompt).width() as u16).min(area.width.saturating_sub(1));
        frame.set_cursor_position((cursor_x, keys.y));
    } else {
        frame.render_widget(fit(key_hints(app.view, theme), width, theme), keys);
    }
}

fn stats_segments<'a>(app: &'a App, theme: &Theme) -> Vec<Vec<Span<'a>>> {
    let CaptureInfo {
        interface,
        status,
        kernel_dropped,
        interface_dropped,
    } = &app.data.capture;
    let counters = &app.data.snapshot.counters;
    let status_style = match status {
        CaptureStatus::Running => Style::default(),
        CaptureStatus::Stopped => theme.dim,
        CaptureStatus::Failed(_) => theme.error,
    };
    let lost = kernel_dropped + interface_dropped;
    let total_flows = app.data.snapshot.flows.len();

    let mut segments = vec![vec![
        Span::styled(interface.to_string(), theme.header),
        Span::raw(" "),
        Span::styled(status.to_string(), status_style),
    ]];
    if app.paused {
        segments.push(vec![Span::styled(" PAUSED ", theme.paused)]);
    }
    segments.push(vec![Span::raw(format!(
        "pkts {}",
        format::count(counters.packets)
    ))]);
    let flows = if app.flow_rows.len() == total_flows {
        format!("flows {total_flows}")
    } else {
        format!("flows {}/{total_flows}", app.flow_rows.len())
    };
    segments.push(vec![Span::raw(flows)]);
    // Packet loss (never seen by this program) and evictions (seen, then
    // forgotten) are different things and are reported separately.
    segments.push(vec![Span::styled(
        format!("lost {}", format::count(lost)),
        if lost > 0 { theme.error } else { theme.dim },
    )]);
    let evicted = counters.flows_evicted + counters.events_evicted;
    if evicted > 0 {
        segments.push(vec![Span::raw(format!(
            "evicted flows {} events {}",
            format::count(counters.flows_evicted),
            format::count(counters.events_evicted)
        ))]);
    }
    segments
}

fn key_hints<'a>(view: View, theme: &Theme) -> Vec<Vec<Span<'a>>> {
    let hint = |key: &'static str, label: &'static str| {
        vec![
            Span::styled(key, theme.header),
            Span::raw(format!(" {label}")),
        ]
    };
    let mut hints = vec![hint("q", "quit")];
    hints.push(hint("Space", "pause"));
    hints.push(hint("Tab", "view"));
    hints.push(hint("/", "filter"));
    match view {
        View::Flows => {
            hints.push(hint("↑↓/jk", "move"));
            hints.push(hint("Enter", "open"));
            hints.push(hint("s", "sort"));
        }
        View::Events => hints.push(hint("↑↓/jk", "move")),
        View::Detail => {
            hints.push(hint("↑↓/jk", "scroll"));
            hints.push(hint("Esc", "back"));
        }
    }
    hints
}

// --- flow list -----------------------------------------------------------

/// Optional column groups, dropped (rates first) as the terminal narrows.
struct FlowColumns {
    traffic: bool,
    packets: bool,
    rates: bool,
}

impl FlowColumns {
    fn for_width(width: u16) -> Self {
        let mut columns = Self {
            traffic: true,
            packets: true,
            rates: true,
        };
        // PROTO + two endpoints + LAST, then the optional groups.
        let needed = |c: &Self| {
            let count =
                4 + 2 * usize::from(c.traffic) + usize::from(c.packets) + 2 * usize::from(c.rates);
            let widths = 5
                + 2 * 21
                + 6
                + 20 * usize::from(c.traffic)
                + 11 * usize::from(c.packets)
                + 24 * usize::from(c.rates);
            widths + count - 1
        };
        for drop in [
            |c: &mut Self| c.packets = false,
            |c: &mut Self| c.rates = false,
            |c: &mut Self| c.traffic = false,
        ] {
            if needed(&columns) > usize::from(width) {
                drop(&mut columns);
            }
        }
        columns
    }
}

fn draw_flows(frame: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    let columns = FlowColumns::for_width(area.width);
    let visible = usize::from(area.height.saturating_sub(1));
    let selected = app.flow_selection.index();
    let window = scroll_window(&mut app.flow_offset, selected, visible, app.flow_rows.len());

    let snapshot = &app.data.snapshot;
    let rows: Vec<Row> = app.flow_rows[window.clone()]
        .iter()
        .map(|&i| flow_row(&snapshot.flows[i], snapshot.taken_at, &columns, theme))
        .collect();

    let mut labels = vec!["PROTO", "LOCAL", "REMOTE"];
    let mut widths = vec![
        Constraint::Length(5),
        Constraint::Fill(1),
        Constraint::Fill(1),
    ];
    if columns.traffic {
        labels.extend(["← IN", "→ OUT"]);
        widths.extend([Constraint::Length(10); 2]);
    }
    if columns.packets {
        labels.push("PKTS ←/→");
        widths.push(Constraint::Length(11));
    }
    if columns.rates {
        labels.extend(["RATE ←", "RATE →"]);
        widths.extend([Constraint::Length(12); 2]);
    }
    labels.push("LAST");
    widths.push(Constraint::Length(6));

    let table = Table::new(rows, widths)
        .header(header_row(labels, theme))
        .row_highlight_style(theme.selected);
    let mut state = TableState::default().with_selected(selected.map(|s| s - window.start));
    frame.render_stateful_widget(table, area, &mut state);
    if app.flow_rows.is_empty() {
        draw_placeholder(frame, area, "no flows (yet)", theme);
    }
}

fn flow_row<'a>(
    flow: &FlowSummary,
    now: std::time::SystemTime,
    columns: &FlowColumns,
    theme: &Theme,
) -> Row<'a> {
    let mut cells = vec![
        Cell::from(flow.protocol.to_string()),
        Cell::from(flow.local.to_string()),
        Cell::from(flow.remote.to_string()),
    ];
    if columns.traffic {
        cells.push(Cell::from(format::bytes(flow.bytes.inbound)).style(theme.inbound));
        cells.push(Cell::from(format::bytes(flow.bytes.outbound)).style(theme.outbound));
    }
    if columns.packets {
        cells.push(Cell::from(format!(
            "{}/{}",
            format::count(flow.packets.inbound),
            format::count(flow.packets.outbound)
        )));
    }
    if columns.rates {
        cells.push(Cell::from(format::rate(flow.rate.inbound)).style(theme.inbound));
        cells.push(Cell::from(format::rate(flow.rate.outbound)).style(theme.outbound));
    }
    let idle = now.duration_since(flow.last_seen).unwrap_or(Duration::ZERO);
    cells.push(Cell::from(format::age(idle)));
    Row::new(cells)
}

fn draw_placeholder(frame: &mut Frame, area: Rect, text: &str, theme: &Theme) {
    let area = Rect {
        y: area.y.saturating_add(2).min(area.bottom()),
        height: area.height.saturating_sub(2).min(1),
        ..area
    };
    frame.render_widget(Paragraph::new(text.to_owned()).style(theme.dim), area);
}

// --- event log -----------------------------------------------------------

struct EventText {
    protocol: &'static str,
    direction: Option<Direction>,
    endpoints: String,
    info: String,
    is_error: bool,
}

fn icmpv6_name(type_u8: u8) -> Option<&'static str> {
    Some(match type_u8 {
        128 => "echo request",
        129 => "echo reply",
        133 => "router solicitation",
        134 => "router advertisement",
        135 => "neighbor solicitation",
        136 => "neighbor advertisement",
        _ => return None,
    })
}

fn describe_net_event(event: &NetEvent) -> EventText {
    let (protocol, info) = match &event.transport {
        Transport::Icmp(IcmpKind::EchoRequest { seq, id }) => {
            ("ICMP", format!("echo request seq={seq} id={id}"))
        }
        Transport::Icmp(IcmpKind::EchoReply { seq, id }) => {
            ("ICMP", format!("echo reply seq={seq} id={id}"))
        }
        Transport::Icmp(IcmpKind::Other(t)) => ("ICMP", format!("type {t}")),
        Transport::Icmpv6 { type_u8 } => (
            "ICMPv6",
            match icmpv6_name(*type_u8) {
                Some(name) => format!("{name} (type {type_u8})"),
                None => format!("type {type_u8}"),
            },
        ),
        Transport::Arp {
            operation,
            sender_mac,
            sender_ip,
            target_ip,
            ..
        } => (
            "ARP",
            match operation {
                1 => format!("who-has {target_ip} tell {sender_ip}"),
                2 => format!("{sender_ip} is-at {sender_mac}"),
                other => format!("operation {other}"),
            },
        ),
        Transport::Tcp { .. } => ("TCP", String::new()),
        Transport::Udp { .. } => ("UDP", String::new()),
    };
    EventText {
        protocol,
        direction: Some(event.direction),
        endpoints: format!("{} → {}", event.source, event.destination),
        info,
        is_error: false,
    }
}

fn describe_unparsed(frame: &UnparsedFrame) -> EventText {
    let (info, is_error) = match (frame.reason, &frame.ethernet) {
        (UnparsedReason::UnsupportedEtherType, Some(eth)) => (
            format!("unsupported EtherType 0x{:04x}", eth.ethertype),
            false,
        ),
        (UnparsedReason::UnsupportedEtherType, None) => ("unsupported EtherType".to_owned(), false),
        (UnparsedReason::UnsupportedProtocol, _) => ("unsupported IP protocol".to_owned(), false),
        (UnparsedReason::Malformed(layer), _) => (format!("malformed {layer} header"), true),
        (UnparsedReason::Fragmented, _) => (
            "IP fragment (transport header unavailable)".to_owned(),
            false,
        ),
        (UnparsedReason::Filtered, _) => ("filtered".to_owned(), false),
    };
    EventText {
        protocol: "N/A",
        direction: None,
        endpoints: frame.ethernet.map_or_else(
            || "-".to_owned(),
            |eth| format!("{} → {}", eth.source, eth.destination),
        ),
        info,
        is_error,
    }
}

fn describe(entry: &EventEntry) -> EventText {
    match &entry.outcome {
        ParseOutcome::Event(event) => describe_net_event(event),
        ParseOutcome::Unparsed(frame) => describe_unparsed(frame),
    }
}

fn draw_events(frame: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    let show_len = area.width >= 72;
    let visible = usize::from(area.height.saturating_sub(1));
    let selected = app.event_selection.index();
    let window = scroll_window(
        &mut app.event_offset,
        selected,
        visible,
        app.event_rows.len(),
    );

    let events = &app.data.snapshot.events;
    let rows: Vec<Row> = app.event_rows[window.clone()]
        .iter()
        .map(|&i| {
            let entry = &events[i];
            let text = describe(entry);
            let direction = match text.direction {
                Some(direction) => Cell::from(direction_span(direction, theme)),
                None => Cell::from("-"),
            };
            let mut cells = vec![
                Cell::from(format::clock(entry.timestamp)),
                Cell::from(text.protocol),
                direction,
                Cell::from(text.endpoints),
                Cell::from(text.info).style(if text.is_error {
                    theme.error
                } else {
                    Style::default()
                }),
            ];
            if show_len {
                cells.push(Cell::from(format!("{} B", entry.wire_len)));
            }
            Row::new(cells)
        })
        .collect();

    let mut labels = vec!["TIME (UTC)", "PROTO", "DIR", "ENDPOINTS", "INFO"];
    let mut widths = vec![
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Fill(2),
        Constraint::Fill(2),
    ];
    if show_len {
        labels.push("LEN");
        widths.push(Constraint::Length(8));
    }
    let table = Table::new(rows, widths)
        .header(header_row(labels, theme))
        .row_highlight_style(theme.selected);
    let mut state = TableState::default().with_selected(selected.map(|s| s - window.start));
    frame.render_stateful_widget(table, area, &mut state);
    if app.event_rows.is_empty() {
        draw_placeholder(frame, area, "no ICMP, ARP or unparsed packets (yet)", theme);
    }
}

// --- flow details --------------------------------------------------------

fn tcp_flags_text(flags: Option<TcpFlags>) -> String {
    let Some(flags) = flags else {
        return "-".to_owned();
    };
    let names = [
        (flags.syn, "SYN"),
        (flags.ack, "ACK"),
        (flags.fin, "FIN"),
        (flags.rst, "RST"),
    ];
    let text: Vec<&str> = names
        .iter()
        .filter(|(set, _)| *set)
        .map(|(_, n)| *n)
        .collect();
    if text.is_empty() {
        "-".to_owned()
    } else {
        text.join(" ")
    }
}

fn summary_lines<'a>(
    state: &DetailState,
    now: std::time::SystemTime,
    theme: &Theme,
) -> Vec<Line<'a>> {
    let flow = &state.detail.summary;
    let status = if state.ended {
        "ended (expired or evicted)"
    } else if flow.closed {
        "closed"
    } else {
        "open"
    };
    let direction_line = |direction: Direction, style: Style| {
        Line::from(vec![
            direction_span(direction, theme),
            Span::styled(
                format!(
                    "  packets {:<8} bytes {:<11} rate {}",
                    flow.packets.get(direction),
                    format::bytes(*flow.bytes.get(direction)),
                    format::rate(*flow.rate.get(direction))
                ),
                style,
            ),
        ])
    };
    let idle = now.duration_since(flow.last_seen).unwrap_or(Duration::ZERO);
    vec![
        Line::from(vec![
            Span::styled(format!("{}  ", flow.protocol), theme.header),
            Span::raw(format!("interface {}  state {status}", flow.interface)),
        ]),
        Line::from(format!("Local   {}", flow.local)),
        Line::from(format!("Remote  {}", flow.remote)),
        direction_line(Direction::Inbound, theme.inbound),
        direction_line(Direction::Outbound, theme.outbound),
        Line::from(format!(
            "Total   packets {}  bytes {}",
            flow.total_packets(),
            format::bytes(flow.total_bytes())
        )),
        Line::from(format!(
            "Active  {} → {} UTC  ({}, last activity {} ago)",
            format::clock(flow.first_seen),
            format::clock(flow.last_seen),
            format::duration(flow.duration()),
            format::age(idle)
        )),
    ]
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    let Some(state) = &app.detail else {
        draw_placeholder(frame, area, "select a flow in the Flows view first", theme);
        return;
    };
    let lines = summary_lines(state, app.data.snapshot.taken_at, theme);
    let summary_height = lines.len() as u16;
    let [summary, history] =
        Layout::vertical([Constraint::Length(summary_height), Constraint::Min(0)]).areas(area);
    frame.render_widget(Paragraph::new(lines), summary);
    draw_history(frame, history, &state.detail, state.scroll, theme);
}

fn draw_history(frame: &mut Frame, area: Rect, detail: &FlowDetail, scroll: usize, theme: &Theme) {
    let total = detail.summary.total_packets();
    let shown = detail.history.len();
    let mut title = format!("Recent packets: last {shown} of {total}");
    if scroll > 0 {
        title.push_str(&format!("  (scrolled back {scroll})"));
    }
    let [title_area, table_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    frame.render_widget(Line::styled(title, theme.header), title_area);

    // Newest packet at the bottom; `scroll` moves the window towards older ones.
    let visible = usize::from(table_area.height.saturating_sub(1));
    let end = shown.saturating_sub(scroll.min(shown.saturating_sub(1)));
    let start = end.saturating_sub(visible);
    let first = detail.summary.first_seen;
    let rows: Vec<Row> = detail.history[start..end]
        .iter()
        .map(|sample| history_row(sample, first, theme))
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Fill(1),
        ],
    )
    .header(header_row(["TIME", "DIR", "LEN", "TCP FLAGS"], theme));
    frame.render_widget(table, table_area);
}

fn history_row<'a>(
    sample: &PacketSample,
    first_seen: std::time::SystemTime,
    theme: &Theme,
) -> Row<'a> {
    let since_first = sample
        .timestamp
        .duration_since(first_seen)
        .unwrap_or(Duration::ZERO);
    let style = match sample.direction {
        Direction::Inbound => theme.inbound,
        Direction::Outbound => theme.outbound,
    };
    Row::new([
        Cell::from(format::offset(since_first)),
        Cell::from(direction_span(sample.direction, theme)),
        Cell::from(format!("{} B", sample.wire_len)),
        Cell::from(tcp_flags_text(sample.flags)),
    ])
    .style(style)
}

#[cfg(test)]
mod tests;
