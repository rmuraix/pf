//! UI state and keyboard handling. No drawing and no I/O happens here.
//!
//! The app works on a [`LiveData`] copy. Pausing simply stops applying new
//! copies; capture and aggregation carry on regardless, so counters are
//! exact again as soon as the display is resumed.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::flow::{FlowDetail, FlowId};
use crate::pipeline::LiveData;

use super::filter::Filter;

/// Rows moved by PageUp / PageDown.
const PAGE: isize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Flows,
    Detail,
    Events,
}

impl View {
    pub const ALL: [View; 3] = [View::Flows, View::Detail, View::Events];

    pub fn title(self) -> &'static str {
        match self {
            Self::Flows => "Flows",
            Self::Detail => "Details",
            Self::Events => "Events",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// Most recently active first.
    Activity,
    /// Most bytes (both directions) first.
    Traffic,
}

impl SortKey {
    pub fn label(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::Traffic => "traffic",
        }
    }
}

/// Keeps a highlighted row on the same item while the list changes under it.
#[derive(Debug, Default)]
pub struct Selection {
    id: Option<u64>,
    index: usize,
}

impl Selection {
    /// Re-finds the selected item in `ids`. If it is gone, the row at the
    /// same position (or the last one) becomes selected.
    fn reconcile(&mut self, ids: &[u64]) {
        let Some(last) = ids.len().checked_sub(1) else {
            *self = Self::default();
            return;
        };
        self.index = match self.id.and_then(|id| ids.iter().position(|&x| x == id)) {
            Some(index) => index,
            None => self.index.min(last),
        };
        self.id = Some(ids[self.index]);
    }

    fn step(&mut self, ids: &[u64], delta: isize) {
        let Some(last) = ids.len().checked_sub(1) else {
            return;
        };
        self.index = self.index.saturating_add_signed(delta).min(last);
        self.id = Some(ids[self.index]);
    }

    pub fn index(&self) -> Option<usize> {
        self.id.map(|_| self.index)
    }
}

/// The flow shown in the details view.
#[derive(Debug)]
pub struct DetailState {
    pub detail: FlowDetail,
    /// The flow expired or was evicted; `detail` is its last known state.
    pub ended: bool,
    /// Packets scrolled back from the newest one.
    pub scroll: usize,
}

pub struct App {
    pub view: View,
    pub paused: bool,
    pub sort: SortKey,
    pub filter_text: String,
    pub editing_filter: bool,
    pub data: LiveData,

    filter: Filter,
    /// Indices into `data.snapshot.flows`, filtered and sorted.
    pub flow_rows: Vec<usize>,
    flow_ids: Vec<FlowId>,
    pub flow_selection: Selection,
    /// Indices into `data.snapshot.events`, newest first.
    pub event_rows: Vec<usize>,
    event_ids: Vec<u64>,
    pub event_selection: Selection,
    /// First visible row of each table; maintained by the renderer.
    pub flow_offset: usize,
    pub event_offset: usize,
    pub detail: Option<DetailState>,

    detail_request: Option<FlowId>,
    refresh_request: bool,
    quit: bool,
}

impl App {
    pub fn new(data: LiveData) -> Self {
        let mut app = Self {
            view: View::Flows,
            paused: false,
            sort: SortKey::Activity,
            filter_text: String::new(),
            editing_filter: false,
            data,
            filter: Filter::default(),
            flow_rows: Vec::new(),
            flow_ids: Vec::new(),
            flow_selection: Selection::default(),
            event_rows: Vec::new(),
            event_ids: Vec::new(),
            event_selection: Selection::default(),
            flow_offset: 0,
            event_offset: 0,
            detail: None,
            detail_request: None,
            refresh_request: false,
            quit: false,
        };
        app.rebuild_rows();
        app
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Set when the display was just resumed and should catch up at once.
    pub fn take_refresh_request(&mut self) -> bool {
        std::mem::take(&mut self.refresh_request)
    }

    /// The flow whose details should be (re)fetched, if any.
    pub fn take_detail_request(&mut self) -> Option<FlowId> {
        self.detail_request.take()
    }

    /// Replaces the displayed data. Ignored while paused.
    pub fn apply(&mut self, data: LiveData) {
        if self.paused {
            return;
        }
        self.data = data;
        self.rebuild_rows();
        if let Some(state) = &self.detail {
            self.detail_request = Some(state.detail.summary.id);
        }
    }

    /// Stores the fetched details; `None` marks the flow as ended, keeping
    /// what was shown before (or the summary from the list if nothing was).
    pub fn set_detail(&mut self, id: FlowId, fetched: Option<FlowDetail>) {
        let scroll = self.detail.as_ref().map_or(0, |d| d.scroll);
        self.detail = match (fetched, self.detail.take()) {
            (Some(detail), _) => Some(DetailState {
                detail,
                ended: false,
                scroll,
            }),
            (None, Some(mut state)) if state.detail.summary.id == id => {
                state.ended = true;
                Some(state)
            }
            (None, _) => self
                .data
                .snapshot
                .flows
                .iter()
                .find(|flow| flow.id == id)
                .map(|summary| DetailState {
                    detail: FlowDetail {
                        summary: summary.clone(),
                        history: Vec::new(),
                        history_capacity: 0,
                    },
                    ended: true,
                    scroll: 0,
                }),
        };
    }

    fn rebuild_rows(&mut self) {
        let snapshot = &self.data.snapshot;
        let flows = &snapshot.flows;
        let mut rows: Vec<usize> = (0..flows.len())
            .filter(|&i| self.filter.matches_flow(&flows[i]))
            .collect();
        // Ties fall back to the id so the order is stable between refreshes.
        match self.sort {
            SortKey::Activity => rows.sort_by(|&a, &b| {
                (flows[b].last_seen, flows[b].id).cmp(&(flows[a].last_seen, flows[a].id))
            }),
            SortKey::Traffic => rows.sort_by(|&a, &b| {
                (flows[b].total_bytes(), flows[b].id).cmp(&(flows[a].total_bytes(), flows[a].id))
            }),
        }
        self.flow_ids = rows.iter().map(|&i| flows[i].id).collect();
        self.flow_rows = rows;
        self.flow_selection.reconcile(&self.flow_ids);

        let events = &snapshot.events;
        self.event_rows = (0..events.len())
            .rev()
            .filter(|&i| self.filter.matches_event(&events[i]))
            .collect();
        self.event_ids = self.event_rows.iter().map(|&i| events[i].seq).collect();
        self.event_selection.reconcile(&self.event_ids);
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.editing_filter {
            self.handle_filter_key(key);
            return;
        }
        // Other Ctrl/Alt chords are not bindings; don't let them act as
        // plain letters.
        if ctrl || key.modifiers.contains(KeyModifiers::ALT) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::PageUp => self.step(-PAGE),
            KeyCode::PageDown => self.step(PAGE),
            KeyCode::Enter => {
                if self.view == View::Flows {
                    self.open_detail();
                }
            }
            KeyCode::Esc => self.back(),
            KeyCode::Tab => self.cycle_view(true),
            KeyCode::BackTab => self.cycle_view(false),
            KeyCode::Char('/') => self.editing_filter = true,
            KeyCode::Char('s') => self.cycle_sort(),
            KeyCode::Char(' ') => self.toggle_pause(),
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        let before = self.filter_text.len();
        match key.code {
            KeyCode::Enter => self.editing_filter = false,
            KeyCode::Esc => {
                self.filter_text.clear();
                self.editing_filter = false;
            }
            KeyCode::Backspace => {
                self.filter_text.pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.filter_text.push(c);
            }
            _ => {}
        }
        if self.filter_text.len() != before {
            self.filter = Filter::parse(&self.filter_text);
            self.rebuild_rows();
        }
    }

    /// Up/Down. In the details view this scrolls the packet history.
    fn step(&mut self, delta: isize) {
        match self.view {
            View::Flows => self.flow_selection.step(&self.flow_ids, delta),
            View::Events => self.event_selection.step(&self.event_ids, delta),
            View::Detail => {
                if let Some(state) = &mut self.detail {
                    let newest = state.detail.history.len().saturating_sub(1);
                    state.scroll = state.scroll.saturating_add_signed(-delta).min(newest);
                }
            }
        }
    }

    fn open_detail(&mut self) -> bool {
        let Some(&id) = self
            .flow_selection
            .index()
            .and_then(|index| self.flow_ids.get(index))
        else {
            return false;
        };
        if self.detail.as_ref().map(|d| d.detail.summary.id) != Some(id) {
            self.detail = None;
        }
        self.detail_request = Some(id);
        self.view = View::Detail;
        true
    }

    /// Esc: leave the current view, or clear an active filter.
    fn back(&mut self) {
        match self.view {
            View::Detail | View::Events => self.view = View::Flows,
            View::Flows => {
                if !self.filter_text.is_empty() {
                    self.filter_text.clear();
                    self.filter = Filter::default();
                    self.rebuild_rows();
                }
            }
        }
    }

    /// Tab / Shift+Tab. The details view is skipped when no flow is selected.
    fn cycle_view(&mut self, forward: bool) {
        let all = View::ALL;
        let current = all.iter().position(|&v| v == self.view).unwrap_or(0);
        for step in 1..=all.len() {
            let offset = if forward { step } else { all.len() - step };
            let next = all[(current + offset) % all.len()];
            match next {
                View::Detail => {
                    if self.open_detail() {
                        return;
                    }
                }
                other => {
                    self.view = other;
                    return;
                }
            }
        }
    }

    fn cycle_sort(&mut self) {
        if self.view != View::Flows {
            return;
        }
        self.sort = match self.sort {
            SortKey::Activity => SortKey::Traffic,
            SortKey::Traffic => SortKey::Activity,
        };
        self.rebuild_rows();
    }

    fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        self.refresh_request = !self.paused;
    }
}

#[cfg(test)]
mod tests;
