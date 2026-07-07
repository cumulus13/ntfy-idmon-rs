// File: src\main.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-06-22
// Description: live download monitor utilizing for idm.internet.download.manager.plus via NTFY
// License: MIT

//! idmon — IDM download monitor
//! Usage:
//!   idmon -n [ntfy_url]        # subscribe to ntfy stream
//!   idmon -H 0.0.0.0 -p 8888  # listen on raw TCP socket
//!   Press 'q' or Ctrl-C to quit

use anyhow::{Context, Result};
use clap::Parser;
use clap_version_flag::colorful_version;
use gntp::{GntpClient, NotificationType, Resource};
use chrono::Local;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    net::TcpStream,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    sync::mpsc,
    time::sleep,
};
use std::collections::VecDeque;

// ratatui
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Terminal,
};

// rasciichart
use rasciichart::{plot_with_config, Config};

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    name = "idmon", 
    about = "IDM Terminal Dynamic Display Stream Engine Infrastructure, live download monitor utilizing for idm.internet.download.manager.plus via NTFY",
    disable_version_flag = true
)]
struct Cli {
    #[arg(short = 'H', long, help = "Bind address string destination target")]
    host: Option<String>,

    #[arg(short = 'p', long, help = "Target connection networking port integer")]
    port: Option<u16>,

    /// Activate stream extraction mode via subscription URL target
    /// Supply URL or omit for default http://localhost:8080/androcall
    #[arg(short = 'n', long, num_args = 0..=1,
          default_missing_value = "http://localhost:8080/androcall")]
    ntfy: Option<String>,

    #[arg(short = 'd', long, help = "Launch low-level terminal telemetry debugging outputs")]
    debug: bool,

    #[arg(long, default_value = "6", help = "Height of speed charts (default: 6)")]
    chart_height: usize,

    #[arg(long, help = "Growl server destination network address target")]
    growl_host: Option<String>,

    #[arg(long, help = "Growl connection network communication port")]
    growl_port: Option<u16>,

    #[arg(long, help = "Growl verification access credential target")]
    growl_password: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileConfig {
    #[serde(default = "default_host")]    host: String,
    #[serde(default = "default_port")]    port: u16,
    #[serde(default = "default_ntfy")]    ntfy_url: String,
    #[serde(default = "default_ghost")]   growl_host: String,
    #[serde(default = "default_gport")]   growl_port: u16,
    #[serde(default)]                     growl_password: String,
}
fn default_host()  -> String { "127.0.0.1".into() }
fn default_port()  -> u16   { 8888 }
fn default_ntfy()  -> String { "http://localhost:8080/androcall".into() }
fn default_ghost() -> String { "127.0.0.1".into() }
fn default_gport() -> u16   { 23053 }

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            host: default_host(), port: default_port(), ntfy_url: default_ntfy(),
            growl_host: default_ghost(), growl_port: default_gport(),
            growl_password: String::new(),
        }
    }
}

fn load_file_config() -> FileConfig {
    let p = PathBuf::from("config.json");
    if p.exists() {
        if let Ok(data) = fs::read_to_string(&p) {
            if let Ok(cfg) = serde_json::from_str::<FileConfig>(&data) {
                return cfg;
            }
        }
    }
    FileConfig::default()
}

#[derive(Debug, Clone)]
struct AppConfig {
    host: String,
    port: u16,
    ntfy_url: String,
    growl_host: String,
    growl_port: u16,
    growl_password: String,
}

fn resolve_config(cli: &Cli) -> AppConfig {
    let f = load_file_config();
    AppConfig {
        host:           cli.host.clone().unwrap_or(f.host),
        port:           cli.port.unwrap_or(f.port),
        ntfy_url:       f.ntfy_url,
        growl_host:     cli.growl_host.clone().unwrap_or(f.growl_host),
        growl_port:     cli.growl_port.unwrap_or(f.growl_port),
        growl_password: cli.growl_password.clone().unwrap_or(f.growl_password),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GNTP / Growl  (manual implementation — avoids gntp crate's edition2024 chain)
// GNTP/1.0 is a plain-text TCP protocol; spec: http://www.growlforwindows.com/gfw/help/gntp.aspx
// ─────────────────────────────────────────────────────────────────────────────
// fn gntp_send(host: &str, port: u16, password: &str, title: &str, message: &str) {
//     // Intentionally ignores errors — fire-and-forget, same as Python version
//     let _ = gntp_send_inner(host, port, password, title, message);
// }

// fn gntp_send_inner(host: &str, port: u16, password: &str, title: &str, message: &str) -> std::io::Result<()> {
//     let addr = format!("{host}:{port}");
//     let mut stream = TcpStream::connect_timeout(
//         &addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
//         Duration::from_secs(3),
//     )?;

//     // ── REGISTER ──────────────────────────────────────────────────────────────
//     // password handling: GNTP supports MD5/SHA hash; empty password = no auth
//     let encryption = if password.is_empty() { "NONE" } else { "NONE" }; // keep simple
//     let register = format!(
//         "GNTP/1.0 REGISTER {encryption}\r\n\
//          Application-Name: NTFY-IDM Monitor\r\n\
//          Notifications-Count: 1\r\n\
//          \r\n\
//          Notification-Name: Download Update\r\n\
//          Notification-Display-Name: Download Update\r\n\
//          Notification-Enabled: True\r\n\
//          \r\n"
//     );
//     stream.write_all(register.as_bytes())?;
//     stream.flush()?;

//     // brief pause for server to process register
//     std::thread::sleep(Duration::from_millis(100));

//     // ── NOTIFY ────────────────────────────────────────────────────────────────
//     let notify = format!(
//         "GNTP/1.0 NOTIFY {encryption}\r\n\
//          Application-Name: NTFY-IDM Monitor\r\n\
//          Notification-Name: Download Update\r\n\
//          Notification-Title: {title}\r\n\
//          Notification-Text: {message}\r\n\
//          \r\n"
//     );
//     stream.write_all(notify.as_bytes())?;
//     stream.flush()?;
//     Ok(())
// }

// fn gntp_send_inner(host: &str, port: u16, password: &str, event_type: &str, title: &str, message: &str) -> std::io::Result<()> {
//     let addr = format!("{host}:{port}");
//     let mut stream = TcpStream::connect_timeout(
//         &addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
//         Duration::from_secs(3),
//     )?;

//     let encryption = if password.is_empty() { "NONE" } else { "NONE" };
    
//     // Define the full list of event names we will use
//     let register = format!(
//         "GNTP/1.0 REGISTER {encryption}\r\n\
//          Application-Name: NTFY-IDM Monitor\r\n\
//          Notifications-Count: 4\r\n\
//          \r\n\
//          Notification-Name: Download Started\r\n\
//          Notification-Display-Name: Download Started\r\n\
//          Notification-Enabled: True\r\n\
//          \r\n\
//          Notification-Name: Download Complete\r\n\
//          Notification-Display-Name: Download Complete\r\n\
//          Notification-Enabled: True\r\n\
//          \r\n\
//          Notification-Name: Download Paused\r\n\
//          Notification-Display-Name: Download Paused\r\n\
//          Notification-Enabled: True\r\n\
//          \r\n\
//          Notification-Name: Download Stopped\r\n\
//          Notification-Display-Name: Download Stopped\r\n\
//          Notification-Enabled: True\r\n\
//          \r\n"
//     );
//     stream.write_all(register.as_bytes())?;
//     stream.flush()?;

//     std::thread::sleep(Duration::from_millis(100));

//     // Dynamic Notification Name mapping based on what event_type is supplied
//     let notify = format!(
//         "GNTP/1.0 NOTIFY {encryption}\r\n\
//          Application-Name: NTFY-IDM Monitor\r\n\
//          Notification-Name: {event_type}\r\n\
//          Notification-Title: {title}\r\n\
//          Notification-Text: {message}\r\n\
//          \r\n"
//     );
//     stream.write_all(notify.as_bytes())?;
//     stream.flush()?;
//     Ok(())
// }

fn gntp_send(host: &str, port: u16, password: &str, event_type: &str, title: &str, message: &str) {
    // Fire-and-forget logic safely wrapped
    let _ = gntp_send_inner(host, port, password, event_type, title, message);
}

fn gntp_send_inner(host: &str, port: u16, password: &str, event_type: &str, title: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = GntpClient::new("NTFY-IDM Monitor")
        .with_host(host)
        .with_port(port);

    if !password.is_empty() {
        client = client.with_password(password);
    }

    // Wrap the string path inside a Resource::Url variant
    // let icon_resource = Resource::Url("idm.png".to_string()); 
    let icon_resource = Resource::from_file("idm.png")?;
    
    // Provision events with our structural icon Resource reference cloned for each state
    let events = vec![
        NotificationType::new("Download Started").with_display_name("Download Started").with_icon(icon_resource.clone()),
        NotificationType::new("Download Complete").with_display_name("Download Complete").with_icon(icon_resource.clone()),
        NotificationType::new("Download Paused").with_display_name("Download Paused").with_icon(icon_resource.clone()),
        NotificationType::new("Download Stopped").with_display_name("Download Stopped").with_icon(icon_resource.clone()),
    ];

    // Register our design details schema definition 
    client.register(events)?;

    // Dispatch the alert notification
    client.notify(event_type, title, message)?;
    
    Ok(())
}

// Adjust proxy wrapper signature
// fn gntp_send(host: &str, port: u16, password: &str, event_type: &str, title: &str, message: &str) {
//     let _ = gntp_send_inner(host, port, password, event_type, title, message);
// }

// ─────────────────────────────────────────────────────────────────────────────
// Speed helpers
// ─────────────────────────────────────────────────────────────────────────────
fn choose_scale(max_val: f64) -> (f64, &'static str) {
    let gb = (1u64 << 30) as f64;
    let mb = (1u64 << 20) as f64;
    let kb = (1u64 << 10) as f64;
    if max_val >= gb { return (gb, "GB"); }
    if max_val >= mb { return (mb, "MB"); }
    if max_val >= kb { return (kb, "KB"); }
    (1.0, "B")
}

fn format_size(bytes: f64) -> String {
    if bytes == 0.0 { return "0 B".into(); }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes;
    for &u in &units {
        if v < 1024.0 { return format!("{v:.1} {u}"); }
        v /= 1024.0;
    }
    format!("{v:.1} PB")
}

fn parse_speed_to_bytes(s: &str) -> f64 {
    let re = Regex::new(r"([0-9.]+)\s*([KMG]?B(?:/S)?)").unwrap();
    let upper = s.to_uppercase();
    if let Some(caps) = re.captures(&upper) {
        let val: f64 = caps[1].parse().unwrap_or(0.0);
        return match &caps[2] {
            u if u.contains("GB") => val * 1_073_741_824.0,
            u if u.contains("MB") => val * 1_048_576.0,
            u if u.contains("KB") => val * 1024.0,
            _ => val,
        };
    }
    0.0
}

// ─────────────────────────────────────────────────────────────────────────────
// Download state
// ─────────────────────────────────────────────────────────────────────────────
const MAX_SAMPLES: usize = 400;
const MAX_COMPLETED_VISIBLE: usize = 5;
const TOP_K_CHARTS: usize = 6;

#[derive(Debug, Clone)]
pub struct DownloadEntry {
    name: String,
    percent: String,
    size: String,
    speed: String,
    eta: String,
    total_duration: String,
    timestamp: String,
    status: &'static str,   // "done" | "stop" | "run"
    completed: bool,
}

#[derive(Debug)]
pub struct DownloadMonitor {
    pub chart_height: usize,
    pub downloads: IndexMap<String, DownloadEntry>,
    speed_history: IndexMap<String, VecDeque<f64>>,
    global_speeds: VecDeque<f64>,
}

impl DownloadMonitor {
    fn new(chart_height: usize) -> Self {
        Self {
            chart_height,
            downloads: IndexMap::new(),
            speed_history: IndexMap::new(),
            global_speeds: VecDeque::with_capacity(MAX_SAMPLES),
        }
    }

    pub fn parse_raw_data(&mut self, raw: &str) -> bool {
        let raw = raw.trim();
        if raw.is_empty() { return false; }

        let Ok(mut v): Result<Value, _> = serde_json::from_str(raw) else { return false; };

        // unwrap nested "message" layers (mirrors Python while loop)
        loop {
            let Some(inner) = v.get("message") else { break };
            if let Some(s) = inner.as_str() {
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    if parsed.is_object() || parsed.is_array() { v = parsed; continue; }
                }
                break;
            } else if inner.is_object() {
                v = inner.clone(); continue;
            }
            break;
        }

        let timestamp = {
            let ts = v.get("time").and_then(|t| t.as_i64())
                .unwrap_or_else(|| std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() as i64);
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| Local::now().format("%Y-%m-%d %H:%M:%S").to_string())
        };

        let name; let percent; let size; let speed; let eta; let total_duration;

        if let Some(title) = v.get("title").and_then(|t| t.as_str()) {
            let clean = title.replace("📱", "");
            let clean = clean.trim();
            if !clean.starts_with("idm.internet.") { return false; }

            let inner_msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
            let lines: Vec<&str> = inner_msg.lines().map(str::trim).filter(|l| !l.is_empty()).collect();

            name = lines.first().copied().unwrap_or("Unknown Asset").to_string();
            let metrics: Vec<&str> = lines.get(1).map(|l| l.split('|').collect()).unwrap_or_default();

            percent        = metrics.first().map(|s| s.trim().to_string()).unwrap_or_else(|| "0%".into());
            size           = metrics.get(1).map(|s| s.trim().to_string()).unwrap_or_else(|| "Unknown Size".into());
            speed          = metrics.get(2).map(|s| s.trim().to_string()).unwrap_or_else(|| "0KB/s".into());
            let time_raw   = metrics.get(3).map(|s| s.trim().to_string()).unwrap_or_else(|| "--/--".into());
            if time_raw.contains('/') {
                let mut it = time_raw.splitn(2, '/');
                eta            = it.next().unwrap_or("--").trim().to_string();
                total_duration = it.next().unwrap_or("--").trim().to_string();
            } else {
                eta = time_raw.trim().to_string();
                total_duration = "--".into();
            }
        } else {
            let val_str = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
            if !val_str.starts_with("idm.internet.") { return false; }
            name = val_str.to_string();
            percent = "0%".into(); size = "Unknown".into(); speed = "0KB/s".into();
            eta = "--".into(); total_duration = "--".into();
        }

        self.update_download(name, percent, size, speed, eta, total_duration, timestamp);
        true
    }

    // fn update_download(
    //     &mut self,
    //     name: String, percent: String, size: String, speed: String,
    //     eta: String, total_duration: String, timestamp: String,
    // ) {
    //     let was_complete = self.downloads.get(&name).map(|e| e.completed).unwrap_or(false);

    //     let is_complete = percent == "100%";
    //     let status: &'static str = if is_complete {
    //         "done"
    //     } else if let Some(prev) = self.downloads.get(&name) {
    //         if !was_complete && prev.speed == speed && prev.percent == percent { "stop" } else { "run" }
    //     } else {
    //         "run"
    //     };

    //     let entry = DownloadEntry {
    //         name: name.clone(), percent, size: size.clone(), speed: speed.clone(),
    //         eta, total_duration, timestamp, status, completed: is_complete,
    //     };

    //     self.downloads.shift_remove(&name);
    //     self.downloads.insert(name.clone(), entry);

    //     // speed telemetry
    //     let speed_bytes = parse_speed_to_bytes(&speed);
    //     let dq = self.speed_history.entry(name.clone()).or_insert_with(|| VecDeque::with_capacity(MAX_SAMPLES));
    //     if dq.len() >= MAX_SAMPLES { dq.pop_front(); }
    //     dq.push_back(speed_bytes);

    //     // global throughput = sum of latest sample per active download
    //     let total_active: f64 = self.downloads.values()
    //         .filter(|e| !e.completed)
    //         .filter_map(|e| self.speed_history.get(&e.name).and_then(|h| h.back()).copied())
    //         .sum();
    //     if self.global_speeds.len() >= MAX_SAMPLES { self.global_speeds.pop_front(); }
    //     self.global_speeds.push_back(total_active);

    //     self.prune_completed();
    // }

    fn update_download(
        &mut self,
        name: String, percent: String, size: String, speed: String,
        eta: String, total_duration: String, timestamp: String,
    ) -> Option<(&'static str, String, String)> { // Returns Option<(EventName, Name, Size)>
        
        // Extract previous status
        let prev_status = self.downloads.get(&name).map(|e| e.status);
        let was_complete = self.downloads.get(&name).map(|e| e.completed).unwrap_or(false);

        let is_complete = percent == "100%";
        let status: &'static str = if is_complete {
            "done"
        } else if let Some(prev) = self.downloads.get(&name) {
            if !was_complete && prev.speed == speed && prev.percent == percent { "stop" } else { "run" }
        } else {
            "run"
        };

        let entry = DownloadEntry {
            name: name.clone(), percent, size: size.clone(), speed: speed.clone(),
            eta, total_duration, timestamp, status, completed: is_complete,
        };

        self.downloads.shift_remove(&name);
        self.downloads.insert(name.clone(), entry);

        // Speed mapping logs...
        let speed_bytes = parse_speed_to_bytes(&speed);
        let dq = self.speed_history.entry(name.clone()).or_insert_with(|| VecDeque::with_capacity(MAX_SAMPLES));
        if dq.len() >= MAX_SAMPLES { dq.pop_front(); }
        dq.push_back(speed_bytes);

        let total_active: f64 = self.downloads.values()
            .filter(|e| !e.completed)
            .filter_map(|e| self.speed_history.get(&e.name).and_then(|h| h.back()).copied())
            .sum();
        if self.global_speeds.len() >= MAX_SAMPLES { self.global_speeds.pop_front(); }
        self.global_speeds.push_back(total_active);

        self.prune_completed();

        // Evaluate Status transitions for alert notifications
        match prev_status {
            None => {
                // Brand new registration into the memory log
                if status == "run" { Some(("Download Started", name, size)) } else { None }
            }
            Some(prev) if prev != status => {
                match status {
                    "done" => Some(("Download Complete", name, size)),
                    "stop" => Some(("Download Stopped", name, size)),
                    "run" if prev == "stop" => Some(("Download Started", name, size)),
                    _ => None
                }
            }
            _ => None
        }
    }

    fn prune_completed(&mut self) {
        let completed: Vec<String> = self.downloads.iter()
            .filter(|(_, e)| e.completed)
            .map(|(k, _)| k.clone())
            .collect();
        if completed.len() > MAX_COMPLETED_VISIBLE {
            for k in &completed[..completed.len() - MAX_COMPLETED_VISIBLE] {
                self.downloads.shift_remove(k);
                self.speed_history.shift_remove(k);
            }
        }
    }

    /// Returns (just_completed_name, just_completed_size) if the last parse triggered completion.
    pub fn last_completed(&self) -> Option<(&str, &str)> {
        self.downloads.values().rev()
            .find(|e| e.completed)
            .map(|e| (e.name.as_str(), e.size.as_str()))
    }

    // ── Charts ────────────────────────────────────────────────────────────────
    fn build_chart_text(&self, term_cols: u16) -> String {
        let mut parts: Vec<String> = Vec::new();

        let global_vec: Vec<f64> = self.global_speeds.iter().copied().collect();
        let max_global = global_vec.iter().cloned().fold(0.0f64, f64::max);
        let (scale, unit) = choose_scale(max_global);
        let unit_label = format!("{unit}/s");

        // axis prefix ≈ "12345.6 ┤" but rasciichart uses its own offset
        let panel_overhead = 6usize;
        let chart_cols = (term_cols as usize).saturating_sub(12 + panel_overhead).max(10);

        let max_label = format!("{}/s", format_size(max_global));
        parts.push(format!("Global throughput ({unit_label})  max {max_label}"));

        let start_g = global_vec.len().saturating_sub(chart_cols);
        let scaled_g: Vec<f64> = global_vec[start_g..].iter().map(|&v| v / scale).collect();

        if scaled_g.len() >= 2 {
            let cfg = Config { height: self.chart_height, width: chart_cols, ..Default::default() };
            match plot_with_config(&scaled_g, cfg) {
                Ok(chart) => parts.push(chart),
                Err(_) => {
                    let s: String = global_vec.iter().rev().take(8).rev()
                        .map(|&v| format!("{}/s", format_size(v))).collect::<Vec<_>>().join(", ");
                    parts.push(s);
                }
            }
        } else {
            parts.push("  Collecting metrics tracking telemetry sequences...".into());
        }

        // ── Per-download mini charts ──────────────────────────────────────────
        let mut active_with_speed: Vec<(&str, f64)> = self.downloads.values()
            .filter(|e| !e.completed)
            .filter_map(|e| {
                self.speed_history.get(&e.name)
                    .and_then(|h| h.back())
                    .map(|&spd| (e.name.as_str(), spd))
            })
            .collect();
        active_with_speed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        if !active_with_speed.is_empty() {
            let individual_height = self.chart_height.max(3) - 1;
            let per_cols = (term_cols as usize).saturating_sub(10 + panel_overhead).max(10);

            parts.push(format!("\nTop file speeds ({unit_label})"));

            for (name, _) in active_with_speed.iter().take(TOP_K_CHARTS) {
                if let Some(series) = self.speed_history.get(*name) {
                    let sv: Vec<f64> = series.iter().copied().collect();
                    let latest = sv.last().copied().unwrap_or(0.0);
                    let latest_label = format!("{}/s", format_size(latest));
                    let short_name = if name.len() > 33 { format!("{}...", &name[..30]) } else { name.to_string() };

                    let start2 = sv.len().saturating_sub(per_cols);
                    let scaled2: Vec<f64> = sv[start2..].iter().map(|&v| v / scale).collect();

                    if scaled2.len() >= 2 {
                        let cfg2 = Config { height: individual_height, width: per_cols, ..Default::default() };
                        match plot_with_config(&scaled2, cfg2) {
                            Ok(g) => parts.push(format!("{short_name} ({latest_label})\n{g}")),
                            Err(_) => {
                                let s: Vec<_> = sv.iter().rev().take(6).rev()
                                    .map(|&v| format!("{}/s", format_size(v))).collect();
                                parts.push(format!("{short_name} ({latest_label}): {}", s.join(", ")));
                            }
                        }
                    } else {
                        let s: Vec<_> = sv.iter().rev().take(6).rev()
                            .map(|&v| format!("{v:.1}")).collect();
                        parts.push(format!("{short_name} ({latest_label}): {}", s.join(", ")));
                    }
                }
            }
        }

        parts.join("\n\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network workers
// ─────────────────────────────────────────────────────────────────────────────
async fn tcp_server_task(host: String, port: u16, tx: mpsc::UnboundedSender<String>) {
    let listener = TcpListener::bind(format!("{host}:{port}")).await
        .expect("Failed to bind TCP listener");
    loop {
        if let Ok((socket, _)) = listener.accept().await {
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(socket).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = tx2.send(line);
                }
            });
        }
    }
}

async fn ntfy_subscriber_task(ntfy_url: String, tx: mpsc::UnboundedSender<String>) {
    let url = if ntfy_url.ends_with("/json") {
        ntfy_url.clone()
    } else {
        format!("{}/json", ntfy_url.trim_end_matches('/'))
    };

    loop {
        match reqwest::get(&url).await {
            Ok(resp) if resp.status().is_success() => {
                use futures_util::StreamExt;
                let mut stream = resp.bytes_stream();
                let mut buf = String::new();
                while let Some(chunk) = stream.next().await {
                    if let Ok(bytes) = chunk {
                        buf.push_str(&String::from_utf8_lossy(&bytes));
                        while let Some(pos) = buf.find('\n') {
                            let line = buf[..pos].trim().to_string();
                            buf = buf[pos + 1..].to_string();
                            if !line.is_empty() { let _ = tx.send(line); }
                        }
                    }
                }
            }
            _ => sleep(Duration::from_secs(5)).await,
        }
        sleep(Duration::from_secs(2)).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TUI
// ─────────────────────────────────────────────────────────────────────────────
fn render_ui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    monitor: &DownloadMonitor,
) -> Result<()> {
    terminal.draw(|frame| {
        let size = frame.size();

        let chart_area_height = (monitor.chart_height * 2 + 10).min(size.height as usize / 2) as u16;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(chart_area_height)])
            .split(size);

        // ── Download table ────────────────────────────────────────────────────
        let downloads: Vec<&DownloadEntry> = monitor.downloads.values().collect();
        let active_count = downloads.iter().filter(|e| !e.completed).count();

        let header = Row::new([
            "  #", "Progress", "Name", "Size", "Speed", "ETA", "Total Duration", "Status", "Timestamp"
        ].iter().map(|h| {
            Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        })).height(1);

        let rows: Vec<Row> = if downloads.is_empty() {
            vec![Row::new(vec![
                Cell::from("-"), Cell::from("-"),
                Cell::from("Awaiting target stream transmission connection..."),
                Cell::from("-"), Cell::from("-"), Cell::from("-"), Cell::from("-"),
                Cell::from("idle"), Cell::from("-"),
            ])]
        } else {
            downloads.iter().enumerate().map(|(i, entry)| {
                let prog = if entry.completed {
                    Cell::from("100%").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                } else {
                    Cell::from(entry.percent.clone()).style(Style::default().fg(Color::Cyan))
                };
                let (status_str, status_color) = match entry.status {
                    "done" => ("✅ done", Color::Green),
                    "stop" => ("🛑 stop", Color::Red),
                    _      => ("⚡ run",  Color::Green),
                };
                Row::new(vec![
                    Cell::from(format!("{}", i + 1)).style(Style::default().fg(Color::Cyan)),
                    prog,
                    Cell::from(entry.name.clone()).style(Style::default().fg(Color::White)),
                    Cell::from(entry.size.clone()).style(Style::default().fg(Color::Green)),
                    Cell::from(entry.speed.clone()).style(Style::default().fg(Color::Yellow)),
                    Cell::from(entry.eta.clone()).style(Style::default().fg(Color::Magenta)),
                    Cell::from(entry.total_duration.clone()).style(Style::default().fg(Color::Blue)),
                    Cell::from(status_str).style(Style::default().fg(status_color)),
                    Cell::from(entry.timestamp.clone()).style(Style::default().fg(Color::DarkGray)),
                ])
            }).collect()
        };

        let table = Table::new(rows, &[
                Constraint::Length(4),
                Constraint::Length(9),
                Constraint::Min(20),
                Constraint::Length(14),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Length(10),
                Constraint::Length(21),
            ])
            .header(header)
            .block(
                Block::default()
                    .title(format!("📡 Live NTFY-IDM Monitor  ({active_count} active)"))
                    .title_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
            );
        frame.render_widget(table, chunks[0]);

        // ── Speed charts ──────────────────────────────────────────────────────
        let chart_text = monitor.build_chart_text(size.width);
        let charts = Paragraph::new(chart_text)
            .block(
                Block::default()
                    .title("📈 Real-Time Speed Telemetry")
                    .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(charts, chunks[1]);
    })?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-V" || args[1] == "--version") {
        let version = colorful_version!();
        version.print_and_exit();
    }

    let cli = Cli::parse();
    let cfg = resolve_config(&cli);
    let debug = cli.debug;

    let monitor = Arc::new(Mutex::new(DownloadMonitor::new(cli.chart_height)));
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // ── network worker ────────────────────────────────────────────────────────
    let is_ntfy = cli.ntfy.is_some();
    let ntfy_url = cli.ntfy.clone().unwrap_or_else(|| cfg.ntfy_url.clone());

    if is_ntfy {
        tokio::spawn(ntfy_subscriber_task(ntfy_url, tx.clone()));
    } else {
        eprintln!("use '-h/--help' for help");
        let h = cfg.host.clone();
        let p = cfg.port;
        tokio::spawn(tcp_server_task(h, p, tx.clone()));
    }

    // ── message processor ─────────────────────────────────────────────────────
    // let monitor2   = Arc::clone(&monitor);
    // let cfg2       = cfg.clone();
    // // let mut prev_completed: std::collections::HashSet<String> = std::collections::HashSet::new();

    // tokio::spawn(async move {
    //     while let Some(line) = rx.recv().await {
    //         if debug { eprintln!("[DEBUG] {line}"); }

    //         let (changed, newly_done) = {
    //             let mut mon = monitor2.lock().unwrap();
    //             let changed = mon.parse_raw_data(&line);
    //             // detect newly completed entries
    //             let newly: Vec<(String, String)> = if changed {
    //                 mon.downloads.values()
    //                     .filter(|e| e.completed && !prev_completed.contains(&e.name))
    //                     .map(|e| (e.name.clone(), e.size.clone()))
    //                     .collect()
    //             } else { vec![] };
    //             (changed, newly)
    //         };

    //         if changed {
    //             for (name, size) in newly_done {
    //                 prev_completed.insert(name.clone());
    //                 let gh  = cfg2.growl_host.clone();
    //                 let gp  = cfg2.growl_port;
    //                 let gpw = cfg2.growl_password.clone();
    //                 let title = "📥 Download Complete!".to_string();
    //                 let msg   = format!("Asset: {name}\nSize: {size}");
    //                 tokio::task::spawn_blocking(move || gntp_send(&gh, gp, &gpw, &title, &msg));
    //             }
    //         }
    //     }
    // });

    // ── message processor ─────────────────────────────────────────────────────
    
    // ── message processor ─────────────────────────────────────────────────────

    // tokio::spawn(async move {
    //     while let Some(line) = rx.recv().await {
    //         if debug { eprintln!("[DEBUG] {line}"); }

    //         // Extract the notification item directly if the download monitor changes state
    //         let notification = {
    //             let mut mon = monitor2.lock().unwrap();
                
    //             // We parse structural payload fields
    //             let raw = line.trim();
    //             if !raw.is_empty() {
    //                 if let Ok(mut v) = serde_json::from_str::<Value>(raw) {
    //                     loop {
    //                         let Some(inner) = v.get("message") else { break };
    //                         if let Some(s) = inner.as_str() {
    //                             if let Ok(parsed) = serde_json::from_str::<Value>(s) {
    //                                 if parsed.is_object() || parsed.is_array() { v = parsed; continue; }
    //                             }
    //                             break;
    //                         } else if inner.is_object() {
    //                             v = inner.clone(); continue;
    //                         }
    //                         break;
    //                     }

    //                     let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    //                     let mut name = String::new();
    //                     let mut percent = String::new();
    //                     let mut size = String::new();
    //                     let mut speed = String::new();
    //                     let mut eta = String::new();
    //                     let mut total_duration = String::new();

    //                     if let Some(title) = v.get("title").and_then(|t| t.as_str()) {
    //                         let clean = title.replace("📱", "");
    //                         let clean = clean.trim();
    //                         if clean.starts_with("idm.internet.") {
    //                             let inner_msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
    //                             let lines: Vec<&str> = inner_msg.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    //                             name = lines.first().copied().unwrap_or("Unknown Asset").to_string();
    //                             let metrics: Vec<&str> = lines.get(1).map(|l| l.split('|').collect()).unwrap_or_default();
    //                             percent = metrics.first().map(|s| s.trim().to_string()).unwrap_or_else(|| "0%".into());
    //                             size = metrics.get(1).map(|s| s.trim().to_string()).unwrap_or_else(|| "Unknown Size".into());
    //                             speed = metrics.get(2).map(|s| s.trim().to_string()).unwrap_or_else(|| "0KB/s".into());
    //                             let time_raw = metrics.get(3).map(|s| s.trim().to_string()).unwrap_or_else(|| "--/--".into());
    //                             if time_raw.contains('/') {
    //                                 let mut it = time_raw.splitn(2, '/');
    //                                 eta = it.next().unwrap_or("--").trim().to_string();
    //                                 total_duration = it.next().unwrap_or("--").trim().to_string();
    //                             } else {
    //                                 eta = time_raw.trim().to_string();
    //                                 total_duration = "--".into();
    //                             }
    //                         }
    //                     }

    //                     if !name.is_empty() {
    //                         // Call our enhanced update handler signature
    //                         mon.update_download(name, percent, size, speed, eta, total_duration, timestamp)
    //                     } else {
    //                         None
    //                     }
    //                 } else { None }
    //             } else { None }
    //         };

    //         // Dispatch dynamic alert via threadpool worker seamlessly
    //         if let Some((event_type, name, size)) = notification {
    //             let gh  = cfg2.growl_host.clone();
    //             let gp  = cfg2.growl_port;
    //             let gpw = cfg2.growl_password.clone();
                
    //             let emoticons = match event_type {
    //                 "Download Complete" => "📥 Done!",
    //                 "Download Started"  => "⚡ Running...",
    //                 "Download Stopped"  => "🛑 Paused/Stopped",
    //                 _                   => "📡 Notice"
    //             };

    //             let title = format!("{emoticons} {event_type}");
    //             let msg   = format!("Asset: {name}\nSize: {size}");
                
    //             tokio::task::spawn_blocking(move || {
    //                 gntp_send(&gh, gp, &gpw, event_type, &title, &msg)
    //             });
    //         }
    //     }
    // });

    // ── message processor ─────────────────────────────────────────────────────
    let monitor2   = Arc::clone(&monitor);
    let cfg2       = cfg.clone();

    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if debug { eprintln!("[DEBUG] {line}"); }

            // Extract event notification triggers after evaluation
            let alert_payload = {
                let mut mon = monitor2.lock().unwrap();
                
                let raw = line.trim();
                if !raw.is_empty() {
                    if let Ok(mut v) = serde_json::from_str::<Value>(raw) {
                        // Unwrap nested payload message layers safely
                        loop {
                            let Some(inner) = v.get("message") else { break };
                            if let Some(s) = inner.as_str() {
                                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                                    if parsed.is_object() || parsed.is_array() { v = parsed; continue; }
                                }
                                break;
                            } else if inner.is_object() {
                                v = inner.clone(); continue;
                            }
                            break;
                        }

                        if let Some(title) = v.get("title").and_then(|t| t.as_str()) {
                            let clean = title.replace("📱", "").trim().to_string();
                            if clean.starts_with("idm.internet.") {
                                let inner_msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
                                let lines: Vec<&str> = inner_msg.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                                let name = lines.first().copied().unwrap_or("Unknown Asset").to_string();
                                
                                // Fetch previous entry status out of the indexmap for comparison
                                let old_status = mon.downloads.get(&name).map(|e| e.status);

                                // Perform core tracking telemetry updates
                                mon.parse_raw_data(&line);

                                // Read new tracking updates safely
                                if let Some(updated_entry) = mon.downloads.get(&name) {
                                    let new_status = updated_entry.status;
                                    let size = updated_entry.size.clone();

                                    // Map status transitions into target notification names
                                    match (old_status, new_status) {
                                        (None, "run") => Some(("Download Started", name, size)),
                                        (Some("stop"), "run") => Some(("Download Started", name, size)),
                                        (Some("run"), "stop") => Some(("Download Stopped", name, size)),
                                        (_, "done") if old_status != Some("done") => Some(("Download Complete", name, size)),
                                        _ => None
                                    }
                                } else { None }
                            } else { None }
                        } else { None }
                    } else { None }
                } else { None }
            };

            // Dispatch notification via the crate-backed implementation wrapper
            if let Some((event_name, asset_name, asset_size)) = alert_payload {
                let gh  = cfg2.growl_host.clone();
                let gp  = cfg2.growl_port;
                let gpw = cfg2.growl_password.clone();

                let decoration = match event_name {
                    "Download Complete" => "📥 Done!",
                    "Download Started"  => "⚡ Running...",
                    "Download Stopped"  => "🛑 Paused/Stopped",
                    _                   => "📡 Update"
                };

                let alert_title = format!("{decoration} {event_name}");
                let alert_msg   = format!("Asset: {asset_name}\nSize: {asset_size}");

                tokio::task::spawn_blocking(move || {
                    gntp_send(&gh, gp, &gpw, event_name, &alert_title, &alert_msg);
                });
            }
        }
    });

    if debug {
        loop { sleep(Duration::from_secs(1)).await; }
    }

    // ── TUI setup ─────────────────────────────────────────────────────────────
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut tick = tokio::time::interval(Duration::from_millis(500));

    loop {
        tick.tick().await;
        {
            let mon = monitor.lock().unwrap();
            render_ui(&mut terminal, &mon)?;
        }
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc) {
                    break;
                }
            }
        }
    }

    // ── TUI teardown ──────────────────────────────────────────────────────────
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    eprintln!("Termination requested. Safe exit operations finalized.");
    Ok(())
}
