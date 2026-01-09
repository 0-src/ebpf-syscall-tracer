use std::{collections::VecDeque, io, sync::mpsc::Receiver, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

const MAX_EVENTS: usize = 500;
const MAX_ALERTS: usize = 200;

pub enum DisplayEvent {
    Trace { kind: &'static str, text: String },
    Alert { rule: &'static str, text: String },
}

struct App {
    events: VecDeque<(&'static str, String)>,
    alerts: VecDeque<(&'static str, String)>,
    event_count: u64,
    alert_count: u64,
}

impl App {
    fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS),
            alerts: VecDeque::with_capacity(MAX_ALERTS),
            event_count: 0,
            alert_count: 0,
        }
    }

    fn push(&mut self, msg: DisplayEvent) {
        match msg {
            DisplayEvent::Trace { kind, text } => {
                self.event_count += 1;
                self.events.push_back((kind, text));
                if self.events.len() > MAX_EVENTS {
                    self.events.pop_front();
                }
            }
            DisplayEvent::Alert { rule, text } => {
                self.alert_count += 1;
                self.alerts.push_back((rule, text));
                if self.alerts.len() > MAX_ALERTS {
                    self.alerts.pop_front();
                }
            }
        }
    }
}

/// Blocking — run on a dedicated thread (`tokio::task::spawn_blocking`), not
/// on an async task, since crossterm's event polling is synchronous.
pub fn run(rx: Receiver<DisplayEvent>) -> io::Result<()> {
    ratatui::run(|terminal| run_app(terminal, rx))
}

fn run_app(terminal: &mut DefaultTerminal, rx: Receiver<DisplayEvent>) -> io::Result<()> {
    let mut app = App::new();
    loop {
        if event::poll(Duration::from_millis(150))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && is_quit_key(key.code, key.modifiers)
        {
            return Ok(());
        }

        while let Ok(msg) = rx.try_recv() {
            app.push(msg);
        }

        terminal.draw(|frame| draw(frame, &app))?;
    }
}

fn is_quit_key(code: KeyCode, modifiers: KeyModifiers) -> bool {
    matches!(code, KeyCode::Char('q')) || (matches!(code, KeyCode::Char('c')) && modifiers.contains(KeyModifiers::CONTROL))
}

fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(35),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let header = Paragraph::new(format!(
        "eBPF Syscall Tracer — {} events, {} alerts — logging to syscall-tracer.jsonl",
        app.event_count, app.alert_count
    ))
    .block(Block::default().borders(Borders::ALL).title("status"));
    frame.render_widget(header, chunks[0]);

    let alert_height = chunks[1].height.saturating_sub(2) as usize;
    let alert_items: Vec<ListItem> = tail(&app.alerts, alert_height)
        .map(|(rule, text)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{rule}] "), Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(text.clone()),
            ]))
            .style(Style::default().fg(Color::Red))
        })
        .collect();
    let alerts_list =
        List::new(alert_items).block(Block::default().borders(Borders::ALL).title(format!("alerts ({})", app.alerts.len())));
    frame.render_widget(alerts_list, chunks[1]);

    let event_height = chunks[2].height.saturating_sub(2) as usize;
    let event_items: Vec<ListItem> = tail(&app.events, event_height)
        .map(|(kind, text)| {
            let color = match *kind {
                "EXEC" => Color::Cyan,
                "WRITE" => Color::Yellow,
                "UNLINK" => Color::Magenta,
                "PTRACE" => Color::Blue,
                _ => Color::White,
            };
            ListItem::new(text.clone()).style(Style::default().fg(color))
        })
        .collect();
    let events_list = List::new(event_items).block(Block::default().borders(Borders::ALL).title("live events"));
    frame.render_widget(events_list, chunks[2]);

    let footer = Paragraph::new("q / Ctrl-C: quit");
    frame.render_widget(footer, chunks[3]);
}

/// Last `n` items of `buf`, oldest first — the window a fixed-height list
/// widget should show when tailing a stream like `tail -f`.
fn tail<T>(buf: &VecDeque<T>, n: usize) -> impl Iterator<Item = &T> {
    let skip = buf.len().saturating_sub(n);
    buf.iter().skip(skip)
}
