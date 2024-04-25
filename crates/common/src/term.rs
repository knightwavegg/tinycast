//! terminal utils
use once_cell::sync::Lazy;
use std::{
    io,
    io::{prelude::*, IsTerminal},
};
use yansi::Paint;

/// Some spinners
// https://github.com/gernest/wow/blob/master/spin/spinners.go
pub static SPINNERS: &[&[&str]] = &[
    &["⠃", "⠊", "⠒", "⠢", "⠆", "⠰", "⠔", "⠒", "⠑", "⠘"],
    &[" ", "⠁", "⠉", "⠙", "⠚", "⠖", "⠦", "⠤", "⠠"],
    &["┤", "┘", "┴", "└", "├", "┌", "┬", "┐"],
    &["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"],
    &[" ", "▘", "▀", "▜", "█", "▟", "▄", "▖"],
];

static TERM_SETTINGS: Lazy<TermSettings> = Lazy::new(TermSettings::from_env);

/// Helper type to determine the current tty
pub struct TermSettings {
    indicate_progress: bool,
}

impl TermSettings {
    /// Returns a new [`TermSettings`], configured from the current environment.
    pub fn from_env() -> TermSettings {
        TermSettings { indicate_progress: std::io::stdout().is_terminal() }
    }
}

#[allow(missing_docs)]
pub struct Spinner {
    indicator: &'static [&'static str],
    no_progress: bool,
    message: String,
    idx: usize,
}

#[allow(unused)]
#[allow(missing_docs)]
impl Spinner {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::with_indicator(SPINNERS[0], msg)
    }

    pub fn with_indicator(indicator: &'static [&'static str], msg: impl Into<String>) -> Self {
        Spinner {
            indicator,
            no_progress: !TERM_SETTINGS.indicate_progress,
            message: msg.into(),
            idx: 0,
        }
    }

    pub fn tick(&mut self) {
        if self.no_progress {
            return
        }

        let indicator = Paint::green(self.indicator[self.idx % self.indicator.len()]);
        let indicator = Paint::new(format!("[{indicator}]")).bold();
        print!("\r\x33[2K\r{indicator} {}", self.message);
        io::stdout().flush().unwrap();

        self.idx = self.idx.wrapping_add(1);
    }

    pub fn message(&mut self, msg: impl Into<String>) {
        self.message = msg.into();
    }
}


#[macro_export]
/// Displays warnings on the cli
macro_rules! cli_warn {
    ($($arg:tt)*) => {
        eprintln!(
            "{}{} {}",
            yansi::Paint::yellow("warning").bold(),
            yansi::Paint::new(":").bold(),
            format_args!($($arg)*)
        )
    }
}

pub use cli_warn;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn can_spin() {
        let mut s = Spinner::new("Compiling".to_string());
        let ticks = 50;
        for _ in 0..ticks {
            std::thread::sleep(std::time::Duration::from_millis(100));
            s.tick();
        }
    }

}
