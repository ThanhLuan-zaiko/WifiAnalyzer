# Nzig

Nzig là ứng dụng CLI phân tích WiFi đa nền tảng, được xây theo mô hình monorepo Rust + Python.

- Rust phụ trách ứng dụng terminal `nzig`, lớp quét WiFi, schema dữ liệu chung và các kernel tính điểm native.
- Python phụ trách lưu trữ DuckDB/Parquet, xử lý dữ liệu bằng Polars, tạo báo cáo và workflow ML.
- `cargo` quản lý phần Rust, còn `uv` quản lý môi trường và thư viện Python.

Nzig là công cụ phân tích thụ động. Ứng dụng chỉ đọc metadata WiFi gần máy thông qua API hoặc công cụ hệ điều hành cung cấp. Nzig không thu mật khẩu, không inject packet, không deauth client và không sniff raw traffic.

Wordlist trong Nzig chỉ được dùng như danh sách marker rủi ro để so khớp SSID/vendor/default pattern trong audit thụ động. Nzig không dùng wordlist để thử mật khẩu, crack handshake, brute-force WPS PIN hoặc truy cập mạng.

## Yêu Cầu

Cài các công cụ sau trước khi clone repo:

- Git.
- Rust toolchain có Cargo. Khuyến nghị cài qua `rustup`.
- `uv` để quản lý virtualenv và dependency Python.
- Python `3.14.x`. Dự án đang pin `>=3.14,<3.15`.
- Windows: Microsoft C++ Build Tools hoặc Visual Studio Build Tools có MSVC toolchain.
- Linux: NetworkManager và lệnh `nmcli` để quét WiFi thật.
- macOS: adapter hiện tại dùng lệnh legacy `airport -s`; các bản macOS mới có thể cần thay adapter bằng CoreWLAN bridge.

Các thư viện Python được khóa trong `uv.lock` và cài bằng `uv sync --dev`. Những thư viện quan trọng:

- `polars`: DataFrame và feature engineering.
- `duckdb`: analytical database cục bộ, dùng làm catalog và query engine.
- `scikit-learn`, `numpy`, `scipy`, `joblib`: train và chạy model ML.
- `maturin`: build Rust PyO3 extension để Python import được backend native.
- `pytest` và `ruff`: test và lint.

Các crate Rust được khóa trong `Cargo.lock`. Những crate quan trọng:

- `clap`: parse CLI command và option.
- `comfy-table`: render bảng trong terminal.
- `pyo3`: tạo Python native extension từ Rust.
- `serde`, `serde_json`: serialize/deserialize contract JSON chung.
- `windows-sys`: truy cập Windows WLAN API.

## Clone Và Thiết Lập

```powershell
git clone <repo-url> Nzig
cd Nzig
uv sync --dev
uv run maturin develop
cargo build --workspace
cargo test --workspace
uv run pytest
```

`uv sync --dev` tạo `.venv/` và cài toàn bộ dependency Python theo `uv.lock`.
`uv run maturin develop` build Rust extension rồi cài vào virtualenv với tên import `wifianalyzer.wifi_backend`.

Nếu Windows báo lỗi quyền khi `uv` ghi cache, dùng cache cục bộ trong repo:

```powershell
$env:UV_CACHE_DIR='.uv-cache-local'
uv sync --dev
uv run maturin develop
```

## Chạy Khi Phát Triển

Khi đang code trong repo, chạy qua Cargo:

```powershell
cargo run -p nzig-cli -- doctor
cargo run -p nzig-cli -- scan --mock
cargo run -p nzig-cli -- scan --mock --save
cargo run -p nzig-cli -- analyze channels --band 2.4 --top 3 --live --mock
cargo run -p nzig-cli -- analyze security --live --mock --wordlist internal-risk-markers.txt
cargo run -p nzig-cli -- history summary
cargo run -p nzig-cli -- model train
cargo run -p nzig-cli -- model predict --band 2.4 --top 3
cargo run -p nzig-cli -- report --format md
```

Nên chạy `--mock` trước. Chế độ này kiểm tra được CLI, Python worker, PyO3 backend, DuckDB/Parquet storage và luồng ML mà không phụ thuộc phần cứng WiFi hoặc quyền quét của hệ điều hành.

## Cài Lệnh `nzig`

Từ thư mục gốc của repo:

```powershell
cargo install --path crates/wifi-cli --locked
nzig doctor
nzig scan --mock
```

Binary sau khi cài có tên là `nzig`, vì vậy người dùng chỉ cần gõ `nzig` trong terminal thay vì lệnh Cargo dài.

Khi cài bằng cách này, `nzig` thường tự tìm được source checkout đã dùng để build. Nếu bạn di chuyển repo hoặc chạy ở máy khác, đặt `NZIG_PROJECT_DIR` trỏ tới thư mục clone:

```powershell
$env:NZIG_PROJECT_DIR='D:\Project\Rust\WifiAnalyzer'
nzig doctor
```

Nếu muốn lưu lịch sử scan ở nơi khác ngoài `data/`, đặt `NZIG_DATA_DIR`:

```powershell
$env:NZIG_DATA_DIR='D:\WifiData\nzig'
nzig scan --save
```

## Quét WiFi Thật

Trên Windows:

```powershell
nzig scan
nzig scan --save
nzig analyze channels --band 2.4 --top 5 --live
```

Nếu Windows không trả về mạng WiFi nào, kiểm tra các điểm sau:

- WiFi radio đang bật.
- Service WLAN AutoConfig đang chạy.
- Quyền Location/privacy cho phép hệ thống quét WiFi.
- Terminal có đủ quyền truy cập WLAN API.

Trên Linux, quét thật cần `nmcli`:

```bash
nzig scan
nzig scan --save
```

Trên macOS, bản hiện tại phụ thuộc lệnh legacy `airport -s`.

## Cấu Trúc Dự Án

- `crates/wifi-core`: schema chung, chuẩn hóa dữ liệu, ánh xạ channel/frequency, tính điểm.
- `crates/wifi-scanner`: trait scanner và adapter theo hệ điều hành.
- `crates/wifi-ffi`: PyO3 extension để Python import dưới tên `wifianalyzer.wifi_backend`.
- `crates/wifi-cli`: Rust package build ra binary `nzig`.
- `python/wifianalyzer`: storage, feature engineering, ML worker và reporting.
- `tests`: test Python.
- `docs/ARCHITECTURE.md`: ranh giới module và quy tắc mở rộng.

## Lệnh Kiểm Tra Trước Khi Commit

```powershell
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
uv run ruff check python tests
uv run pytest
```

Nếu đổi dependency hoặc rebuild PyO3 extension, chạy lại:

```powershell
uv sync --dev
uv run maturin develop
```
