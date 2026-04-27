mod worker;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use wifi_core::{recommend_channels, ScanRecord};
use wifi_scanner::{default_scanner, MockScanner, WifiScanner};

#[derive(Debug, Parser)]
#[command(
    name = "nzig",
    bin_name = "nzig",
    version,
    about = "Nzig is a passive WiFi analysis CLI. It reads nearby access-point metadata from operating-system APIs, stores optional scan history, recommends cleaner channels, trains/predicts channel choices, and reports security posture from scan metadata.\n\nNzig la cong cu phan tich WiFi thu dong. Cong cu chi doc metadata access point tu API he dieu hanh, co the luu lich su scan, goi y kenh sach hon, train/predict lua chon kenh, va bao cao tu the bao mat dua tren metadata.",
    after_help = "Safety / An toan:\n  Nzig does not collect passwords, capture handshakes, sniff raw traffic, inject packets, deauth clients, or attempt access.\n  Nzig khong thu mat khau, khong bat handshake, khong sniff raw traffic, khong inject packet, khong deauth client, va khong thu truy cap.\n\nQuick examples / Vi du nhanh:\n  nzig doctor\n  nzig scan --mock\n  nzig scan --save\n  nzig analyze channels --band 2.4 --top 3 --live\n  nzig analyze security --live --mock\n  nzig report --format md\n\nEnvironment / Bien moi truong:\n  NZIG_PROJECT_DIR  Path to this source checkout when an installed nzig cannot locate it.\n  NZIG_DATA_DIR     Directory for saved scans, DuckDB catalog, and reports."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(
        about = "Check local scanner and worker dependencies. / Kiem tra scanner va worker."
    )]
    Doctor,
    #[command(about = "Scan nearby WiFi access points. / Quet cac access point WiFi gan may.")]
    Scan(ScanArgs),
    #[command(about = "Analyze scan data. / Phan tich du lieu WiFi da quet.")]
    Analyze {
        #[command(subcommand)]
        command: AnalyzeCommand,
    },
    #[command(about = "Inspect saved scan history. / Xem lich su scan da luu.")]
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    #[command(
        about = "Train or run channel recommendation models. / Train hoac chay model goi y kenh."
    )]
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },
    #[command(about = "Build a report from saved scans. / Tao bao cao tu scan da luu.")]
    Report(ReportArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(
        long,
        help = "Save scan records to local storage. / Luu ket qua scan vao storage cuc bo."
    )]
    save: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, help = "Output format. / Dinh dang dau ra.")]
    format: OutputFormat,
    #[arg(
        long,
        help = "Use deterministic sample data instead of hardware scan. / Dung du lieu mau thay vi quet phan cung."
    )]
    mock: bool,
}

#[derive(Debug, Subcommand)]
enum AnalyzeCommand {
    #[command(about = "Recommend cleaner WiFi channels. / Goi y kenh WiFi it nhieu hon.")]
    Channels(ChannelArgs),
    #[command(about = "Audit passive security metadata. / Kiem tra bao mat thu dong tu metadata.")]
    Security(SecurityArgs),
}

#[derive(Debug, Args)]
struct ChannelArgs {
    #[arg(
        long,
        default_value = "2.4",
        help = "WiFi band: 2.4, 5, or 6. / Bang tan WiFi: 2.4, 5, hoac 6."
    )]
    band: String,
    #[arg(
        long,
        default_value_t = 5,
        help = "Maximum rows to return. / So dong toi da."
    )]
    top: usize,
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, help = "Output format. / Dinh dang dau ra.")]
    format: OutputFormat,
    #[arg(
        long,
        help = "Scan now and analyze the live records. / Quet ngay va phan tich ket qua hien tai."
    )]
    live: bool,
    #[arg(
        long,
        help = "Use deterministic sample data with --live. / Dung du lieu mau khi co --live."
    )]
    mock: bool,
}

#[derive(Debug, Args)]
struct SecurityArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, help = "Output format. / Dinh dang dau ra.")]
    format: OutputFormat,
    #[arg(
        long,
        help = "Scan now and analyze the live records. / Quet ngay va phan tich ket qua hien tai."
    )]
    live: bool,
    #[arg(
        long,
        help = "Use deterministic sample data with --live. / Dung du lieu mau khi co --live."
    )]
    mock: bool,
    #[arg(long, value_enum, default_value_t = Severity::Info, help = "Minimum severity to show. / Muc do toi thieu can hien thi.")]
    min_severity: Severity,
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    #[command(about = "Summarize saved scan sessions. / Tom tat cac phien scan da luu.")]
    Summary {
        #[arg(long, value_enum, default_value_t = OutputFormat::Json, help = "Output format. / Dinh dang dau ra.")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum ModelCommand {
    #[command(
        about = "Train the channel model from saved scans. / Train model kenh tu scan da luu."
    )]
    Train,
    #[command(
        about = "Predict recommended channels with the trained model. / Du doan kenh goi y bang model."
    )]
    Predict(ChannelArgs),
}

#[derive(Debug, Args)]
struct ReportArgs {
    #[arg(long, value_enum, default_value_t = ReportFormat::Md, help = "Report format. / Dinh dang bao cao.")]
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => doctor(),
        Commands::Scan(args) => scan(args),
        Commands::Analyze {
            command: AnalyzeCommand::Channels(args),
        } => analyze_channels(args),
        Commands::Analyze {
            command: AnalyzeCommand::Security(args),
        } => analyze_security(args),
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

fn analyze_security(args: SecurityArgs) -> Result<()> {
    let min_severity = args.min_severity.as_str();
    let live_records;
    let mut command = vec!["security-audit", "--min-severity", min_severity];

    let input = if args.live {
        live_records = serde_json::to_string(&run_scan(args.mock)?)?;
        command.push("--stdin");
        Some(live_records.as_str())
    } else {
        None
    };

    let output = worker::run(&command, input)?;
    print_json_or_table(&output, args.format, SecurityTable)
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

struct SecurityTable;

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

impl TableRenderer for SecurityTable {
    fn render(&self, value: &serde_json::Value) -> Result<()> {
        let rows = value.as_array().context("expected JSON array")?;
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec![
            "Severity", "Score", "SSID", "BSSID", "Security", "Findings",
        ]);
        for row in rows {
            table.add_row(vec![
                json_cell(row, "severity"),
                json_cell(row, "risk_score"),
                json_cell(row, "ssid"),
                json_cell(row, "bssid"),
                json_cell(row, "security"),
                findings_cell(row),
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

fn findings_cell(value: &serde_json::Value) -> String {
    value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
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
