mod worker;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use wifi_core::{recommend_channels, ScanRecord};
use wifi_scanner::{default_scanner, MockScanner, WifiScanner};

#[derive(Debug, Parser)]
#[command(
    name = "nzig",
    version,
    about = "Analyze nearby WiFi networks from the terminal."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Doctor,
    Scan(ScanArgs),
    Analyze {
        #[command(subcommand)]
        command: AnalyzeCommand,
    },
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },
    Report(ReportArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(long)]
    save: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,
    #[arg(long)]
    mock: bool,
}

#[derive(Debug, Subcommand)]
enum AnalyzeCommand {
    Channels(ChannelArgs),
}

#[derive(Debug, Args)]
struct ChannelArgs {
    #[arg(long, default_value = "2.4")]
    band: String,
    #[arg(long, default_value_t = 5)]
    top: usize,
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,
    #[arg(long)]
    live: bool,
    #[arg(long)]
    mock: bool,
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    Summary {
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum ModelCommand {
    Train,
    Predict(ChannelArgs),
}

#[derive(Debug, Args)]
struct ReportArgs {
    #[arg(long, value_enum, default_value_t = ReportFormat::Md)]
    format: ReportFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Md,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => doctor(),
        Commands::Scan(args) => scan(args),
        Commands::Analyze {
            command: AnalyzeCommand::Channels(args),
        } => analyze_channels(args),
        Commands::History {
            command: HistoryCommand::Summary { format },
        } => worker_passthrough(&["history-summary"], format),
        Commands::Model {
            command: ModelCommand::Train,
        } => worker_passthrough(&["model-train"], OutputFormat::Json),
        Commands::Model {
            command: ModelCommand::Predict(args),
        } => model_predict(args),
        Commands::Report(args) => report(args),
    }
}

fn doctor() -> Result<()> {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Check", "Status", "Detail"]);
    table.add_row(vec!["scanner", "ok", default_scanner().name()]);
    table.add_row(tool_status("cargo", &["--version"]));
    table.add_row(tool_status("uv", &["--version"]));
    table.add_row(tool_status("python", &["--version"]));

    let python_status = match worker::run(&["doctor"], None) {
        Ok(output) => ("ok", output.trim().to_owned()),
        Err(error) => ("warn", error.to_string()),
    };
    table.add_row(vec![
        Cell::new("python-worker"),
        Cell::new(python_status.0),
        Cell::new(python_status.1),
    ]);

    println!("{table}");
    Ok(())
}

fn scan(args: ScanArgs) -> Result<()> {
    let records = run_scan(args.mock)?;
    if args.save {
        let input = serde_json::to_string(&records)?;
        let output = worker::run(&["ingest"], Some(&input))
            .context("failed to save scan via Python worker")?;
        eprintln!("{}", output.trim());
    }

    print_records(&records, args.format)
}

fn analyze_channels(args: ChannelArgs) -> Result<()> {
    if args.live {
        let records = run_scan(args.mock)?;
        let input = serde_json::to_string(&records)?;
        let output = worker::run(
            &[
                "recommend",
                "--stdin",
                "--band",
                &args.band,
                "--top",
                &args.top.to_string(),
            ],
            Some(&input),
        )
        .unwrap_or_else(|_| {
            serde_json::to_string(&recommend_channels(&records, &args.band, args.top))
                .expect("recommendations should serialize")
        });
        return print_json_or_table(&output, args.format, RecommendationTable);
    }

    let output = worker::run(
        &[
            "recommend",
            "--band",
            &args.band,
            "--top",
            &args.top.to_string(),
        ],
        None,
    )?;
    print_json_or_table(&output, args.format, RecommendationTable)
}

fn model_predict(args: ChannelArgs) -> Result<()> {
    let mut command = vec!["model-predict", "--band", &args.band, "--top"];
    let top = args.top.to_string();
    command.push(&top);

    let live_records;
    let input = if args.live {
        live_records = serde_json::to_string(&run_scan(args.mock)?)?;
        command.push("--stdin");
        Some(live_records.as_str())
    } else {
        None
    };

    let output = worker::run(&command, input)?;
    print_json_or_table(&output, args.format, RecommendationTable)
}

fn report(args: ReportArgs) -> Result<()> {
    let format = match args.format {
        ReportFormat::Md => "md",
        ReportFormat::Json => "json",
    };
    let output = worker::run(&["report", "--format", format], None)?;
    println!("{}", output.trim());
    Ok(())
}

fn worker_passthrough(args: &[&str], format: OutputFormat) -> Result<()> {
    let output = worker::run(args, None)?;
    match format {
        OutputFormat::Json => println!("{}", output.trim()),
        OutputFormat::Table => println!("{}", output.trim()),
    }
    Ok(())
}

fn run_scan(mock: bool) -> Result<Vec<ScanRecord>> {
    let scanner: Box<dyn WifiScanner + Send + Sync> = if mock {
        Box::<MockScanner>::default()
    } else {
        default_scanner()
    };
    scanner.scan()
}

fn print_records(records: &[ScanRecord], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(records)?);
        }
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec![
                "SSID", "BSSID", "Band", "Ch", "Freq", "RSSI", "Security",
            ]);
            for record in records {
                table.add_row(vec![
                    record.ssid.clone().unwrap_or_else(|| "<hidden>".to_owned()),
                    record.bssid.clone().unwrap_or_default(),
                    record.band.clone().unwrap_or_default(),
                    record
                        .channel
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    record
                        .frequency_mhz
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    record
                        .rssi_dbm
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    record.security.clone().unwrap_or_default(),
                ]);
            }
            println!("{table}");
        }
    }
    Ok(())
}

trait TableRenderer {
    fn render(&self, value: &serde_json::Value) -> Result<()>;
}

struct RecommendationTable;

impl TableRenderer for RecommendationTable {
    fn render(&self, value: &serde_json::Value) -> Result<()> {
        let rows = value.as_array().context("expected JSON array")?;
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec![
            "Band",
            "Ch",
            "Freq",
            "Score",
            "Interference",
            "APs",
            "Strong",
            "Reason",
        ]);
        for row in rows {
            table.add_row(vec![
                json_cell(row, "band"),
                json_cell(row, "channel"),
                json_cell(row, "frequency_mhz"),
                json_cell(row, "score"),
                json_cell(row, "interference"),
                json_cell(row, "visible_aps"),
                json_cell(row, "strong_aps"),
                json_cell(row, "reason"),
            ]);
        }
        println!("{table}");
        Ok(())
    }
}

fn print_json_or_table<T: TableRenderer>(
    output: &str,
    format: OutputFormat,
    renderer: T,
) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", output.trim()),
        OutputFormat::Table => {
            let value: serde_json::Value = serde_json::from_str(output)?;
            renderer.render(&value)?;
        }
    }
    Ok(())
}

fn json_cell(value: &serde_json::Value, key: &str) -> String {
    match value.get(key) {
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn tool_status(command: &str, args: &[&str]) -> Vec<Cell> {
    match std::process::Command::new(command).args(args).output() {
        Ok(output) if output.status.success() => vec![
            Cell::new(command),
            Cell::new("ok"),
            Cell::new(String::from_utf8_lossy(&output.stdout).trim()),
        ],
        Ok(output) => vec![
            Cell::new(command),
            Cell::new("fail"),
            Cell::new(String::from_utf8_lossy(&output.stderr).trim()),
        ],
        Err(error) => vec![Cell::new(command), Cell::new("fail"), Cell::new(error)],
    }
}
