//! Styles. Direction is always shown with arrows and `IN`/`OUT` labels too,
//! so the monochrome theme loses nothing but colour.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub inbound: Style,
    pub outbound: Style,
    pub selected: Style,
    pub header: Style,
    pub tab_active: Style,
    pub dim: Style,
    pub paused: Style,
    pub error: Style,
}

impl Theme {
    pub fn color() -> Self {
        let bold = Modifier::BOLD;
        Self {
            inbound: Style::new().fg(Color::Cyan),
            outbound: Style::new().fg(Color::Yellow),
            selected: Style::new().add_modifier(Modifier::REVERSED),
            header: Style::new().add_modifier(bold),
            tab_active: Style::new().fg(Color::Black).bg(Color::White),
            dim: Style::new().fg(Color::DarkGray),
            paused: Style::new()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(bold),
            error: Style::new().fg(Color::Red).add_modifier(bold),
        }
    }

    /// No colours at all: attributes only.
    pub fn monochrome() -> Self {
        let reversed = Modifier::REVERSED;
        Self {
            inbound: Style::new(),
            outbound: Style::new().add_modifier(Modifier::BOLD),
            selected: Style::new().add_modifier(reversed),
            header: Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            tab_active: Style::new().add_modifier(reversed),
            dim: Style::new(),
            paused: Style::new().add_modifier(reversed | Modifier::BOLD),
            error: Style::new().add_modifier(reversed | Modifier::BOLD),
        }
    }

    pub fn new(color: bool) -> Self {
        if color {
            Self::color()
        } else {
            Self::monochrome()
        }
    }
}
