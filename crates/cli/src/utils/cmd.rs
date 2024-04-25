use alloy_json_abi::JsonAbi;
use eyre::Result;
use foundry_common::TestFunctionExt;
use std::fmt::Write;
use yansi::Paint;

/// Returns error if constructor has arguments.
pub fn ensure_clean_constructor(abi: &JsonAbi) -> Result<()> {
    if let Some(constructor) = &abi.constructor {
        if !constructor.inputs.is_empty() {
            eyre::bail!("Contract constructor should have no arguments. Add those arguments to  `run(...)` instead, and call it with `--sig run(...)`.");
        }
    }
    Ok(())
}

pub fn needs_setup(abi: &JsonAbi) -> bool {
    let setup_fns: Vec<_> = abi.functions().filter(|func| func.name.is_setup()).collect();

    for setup_fn in setup_fns.iter() {
        if setup_fn.name != "setUp" {
            println!(
                "{} Found invalid setup function \"{}\" did you mean \"setUp()\"?",
                Paint::yellow("Warning:").bold(),
                setup_fn.signature()
            );
        }
    }

    setup_fns.len() == 1 && setup_fns[0].name == "setUp"
}

pub fn eta_key(state: &indicatif::ProgressState, f: &mut dyn Write) {
    write!(f, "{:.1}s", state.eta().as_secs_f64()).unwrap()
}

#[macro_export]
macro_rules! init_progress {
    ($local:expr, $label:expr) => {{
        let pb = indicatif::ProgressBar::new($local.len() as u64);
        let mut template =
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ".to_string();
        template += $label;
        template += " ({eta})";
        pb.set_style(
            indicatif::ProgressStyle::with_template(&template)
                .unwrap()
                .with_key("eta", $crate::utils::eta_key)
                .progress_chars("#>-"),
        );
        pb
    }};
}

#[macro_export]
macro_rules! update_progress {
    ($pb:ident, $index:expr) => {
        $pb.set_position(($index + 1) as u64);
    };
}
