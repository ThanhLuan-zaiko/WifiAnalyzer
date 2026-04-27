use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

pub fn run(args: &[&str], input: Option<&str>) -> Result<String> {
    let mut command = Command::new("uv");
    command.current_dir(project_dir()?);
    command.args(["run", "python", "-m", "wifianalyzer.worker"]);
    command.args(args);
    if env::var_os("UV_CACHE_DIR").is_none() {
        command.env("UV_CACHE_DIR", "target/uv-cache");
    }
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }

    let mut child = command
        .spawn()
        .context("failed to spawn uv Python worker")?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().context("failed to open worker stdin")?;
        stdin.write_all(input.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "worker failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn project_dir() -> Result<PathBuf> {
    if let Some(path) = env::var_os("NZIG_PROJECT_DIR") {
        return validate_project_dir(PathBuf::from(path));
    }

    if let Ok(current_dir) = env::current_dir() {
        for candidate in current_dir.ancestors() {
            if is_project_dir(candidate) {
                return Ok(candidate.to_path_buf());
            }
        }
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo_root) = manifest_dir.parent().and_then(Path::parent) {
        if is_project_dir(repo_root) {
            return Ok(repo_root.to_path_buf());
        }
    }

    bail!(
        "cannot locate Nzig project root; run inside the repo or set NZIG_PROJECT_DIR to the clone path"
    )
}

fn validate_project_dir(path: PathBuf) -> Result<PathBuf> {
    if is_project_dir(&path) {
        Ok(path)
    } else {
        bail!(
            "NZIG_PROJECT_DIR does not look like a Nzig repo: {}",
            path.display()
        )
    }
}

fn is_project_dir(path: &Path) -> bool {
    path.join("pyproject.toml").is_file() && path.join("python").join("wifianalyzer").is_dir()
}
