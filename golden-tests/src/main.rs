use anyhow::{Context, bail};
use std::path::PathBuf;
use std::process::Command;

static EXPECTED_STDOUT_FILE: &str = "expected-stdout";
static EXPECTED_REPLAY_LOG_FILE: &str = "expected-replay-log";

struct TestCase {
    dir: PathBuf,
    name: String,
    args: String,
    expected_stdout: Option<String>,
    expected_replay_log: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let mut test_cases = Vec::new();
    let test_dirs =
        std::fs::read_dir("golden-tests/tests").context("golden tests root directory not found")?;
    for entry in test_dirs {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            println!(
                "skipping path `{}` because it's not a directory",
                path.display()
            );
            continue;
        }

        let args_path = path.join("args");
        let args = std::fs::read_to_string(&args_path)
            .with_context(|| format!("no `args` file found at `{}`", args_path.display()))?;

        let stdout_path = path.join(EXPECTED_STDOUT_FILE);
        let stdout = if stdout_path.is_file() {
            Some(std::fs::read_to_string(&stdout_path).with_context(|| {
                format!(
                    "no `{EXPECTED_STDOUT_FILE}` file found at `{}`",
                    stdout_path.display()
                )
            })?)
        } else {
            None
        };

        let replay_log_path = path.join(EXPECTED_REPLAY_LOG_FILE);
        let replay_log = if replay_log_path.is_file() {
            Some(std::fs::read_to_string(&replay_log_path).with_context(|| {
                format!(
                    "no `{EXPECTED_REPLAY_LOG_FILE}` file found at `{}`",
                    replay_log_path.display()
                )
            })?)
        } else {
            None
        };

        test_cases.push(TestCase {
            name: path.display().to_string(),
            dir: path,
            args,
            expected_stdout: stdout,
            expected_replay_log: replay_log,
        })
    }

    let mut errored = false;
    for test_case in test_cases {
        let name = test_case.name.clone();
        if let Err(e) = run_quinn_workbench(test_case) {
            println!("Error running golden test `{name}`");
            match e {
                TestError::Internal(e) => println!("{e:?}"),
                TestError::Compare(e) => {
                    if let Some(diff) = e.replay_log_diff {
                        println!("Expected replay log differs from actual replay log:\n{diff}\n");
                    }

                    if let Some(diff) = e.stdout_diff {
                        println!("Expected stdout differs from actual stdout:\n{diff}");
                    }
                }
            }
            errored = true;
        } else {
            println!("{name}: ✅");
        }
    }

    if errored {
        bail!("one or more golden tests failed");
    }

    Ok(())
}

enum TestError {
    Internal(anyhow::Error),
    Compare(CompareError),
}

struct CompareError {
    stdout_diff: Option<String>,
    replay_log_diff: Option<String>,
}

fn run_quinn_workbench(test_case: TestCase) -> Result<(), TestError> {
    let workbench_args = test_case.args.split_whitespace();
    let command = Command::new("cargo")
        .arg("run")
        .arg("--release")
        .arg("--bin")
        .arg("quinn-workbench")
        .arg("--")
        .args(workbench_args)
        .output()
        .context("quinn-workbench process crashed")
        .map_err(TestError::Internal)?;

    let stdout = String::from_utf8_lossy(&command.stdout);
    let replay_log = std::fs::read_to_string("replay-log.json")
        .context("failed to read replay-log.json")
        .map_err(TestError::Internal)?;

    let mut stdout_diff = None;
    match test_case.expected_stdout {
        Some(expected_stdout) => {
            if expected_stdout != stdout {
                stdout_diff = Some(diff::diff_to_string(&expected_stdout, &stdout));
            }
        }
        None => {
            std::fs::write(test_case.dir.join(EXPECTED_STDOUT_FILE), stdout.as_bytes())
                .context("failed to persist stdout")
                .map_err(TestError::Internal)?;
        }
    }

    let mut replay_log_diff = None;
    match test_case.expected_replay_log {
        Some(expected_replay_log) => {
            if expected_replay_log != replay_log {
                replay_log_diff = Some(diff::diff_to_string(&expected_replay_log, &replay_log));
            }
        }
        None => {
            std::fs::write(
                test_case.dir.join(EXPECTED_REPLAY_LOG_FILE),
                replay_log.as_bytes(),
            )
            .context("failed to persist replay log")
            .map_err(TestError::Internal)?;
        }
    }

    if stdout_diff.is_some() || replay_log_diff.is_some() {
        Err(TestError::Compare(CompareError {
            stdout_diff,
            replay_log_diff,
        }))
    } else {
        Ok(())
    }
}

mod diff {
    use console::{Style, style};
    use similar::{ChangeTag, TextDiff};
    use std::fmt::{self, Write};

    struct Line(Option<usize>);

    impl fmt::Display for Line {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self.0 {
                None => write!(f, "    "),
                Some(idx) => write!(f, "{:<4}", idx + 1),
            }
        }
    }

    pub fn diff_to_string(old: &str, new: &str) -> String {
        let mut output = String::new();
        let diff = TextDiff::from_lines(old, new);

        for (idx, group) in diff.grouped_ops(3).iter().enumerate() {
            if idx > 0 {
                _ = writeln!(output, "{:-^1$}", "-", 80);
            }
            for op in group {
                for change in diff.iter_inline_changes(op) {
                    let (sign, s) = match change.tag() {
                        ChangeTag::Delete => ("-", Style::new().red()),
                        ChangeTag::Insert => ("+", Style::new().green()),
                        ChangeTag::Equal => (" ", Style::new().dim()),
                    };
                    _ = write!(
                        output,
                        "{}{} |{}",
                        style(Line(change.old_index())).dim(),
                        style(Line(change.new_index())).dim(),
                        s.apply_to(sign).bold(),
                    );
                    for (emphasized, value) in change.iter_strings_lossy() {
                        if emphasized {
                            _ = write!(output, "{}", s.apply_to(value).underlined().on_black());
                        } else {
                            _ = write!(output, "{}", s.apply_to(value));
                        }
                    }
                    if change.missing_newline() {
                        _ = writeln!(output);
                    }
                }
            }
        }

        output
    }
}
