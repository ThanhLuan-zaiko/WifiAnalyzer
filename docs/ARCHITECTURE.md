# Kiến Trúc Nzig

## Ranh Giới Module

- `crates/wifi-cli` tạo binary Rust `nzig` cho người dùng cuối. Module này
  render output trong terminal, chạy scan, và gọi Python worker cho các tác vụ
  phân tích.
- `wifi-core` quản lý contract dữ liệu ổn định: schema scan, chuẩn hóa record,
  ánh xạ channel/frequency, và thuật toán tính điểm kênh.
- `wifi-scanner` quản lý tích hợp hệ điều hành thông qua trait `WifiScanner`.
  Khi thêm backend cho nền tảng mới, chỉ nên mở rộng module này và trả về
  `ScanRecord` đã chuẩn hóa.
- `wifi-ffi` expose một phần kernel của `wifi-core` sang Python thông qua PyO3
  dưới tên `wifianalyzer.wifi_backend`.
- `python/wifianalyzer` quản lý lưu trữ, feature engineering, train/predict mô
  hình ML, và tạo báo cáo.

## Luồng Dữ Liệu

1. `nzig scan` dùng `wifi-scanner` để thu metadata các access point gần máy.
2. Rust chuẩn hóa record bằng `wifi-core` và có thể render ngay ra table hoặc
   JSON.
3. `nzig scan --save` gửi record sang `uv run python -m wifianalyzer.worker ingest`.
4. Python lưu snapshot dạng Parquet trong `data/raw/date=YYYY-MM-DD/` và đăng
   ký session trong DuckDB.
5. Gợi ý kênh WiFi dùng kernel tính điểm Rust qua PyO3; khi native backend
   chưa build, Python có fallback để phục vụ phát triển.
6. ML training dùng lịch sử scan đã lưu để bootstrap model từ nhãn giả do thuật
   toán deterministic scoring tạo ra.

## Quy Tắc Mở Rộng

- Thêm logic quét theo hệ điều hành bằng cách implement `WifiScanner` và trả về
  `ScanRecord`.
- Scanner chỉ được phân tích thụ động: không packet injection, không truy cập
  credential, không deauth, và không raw traffic capture.
- Wordlist chỉ được dùng trong audit thụ động như marker SSID/vendor/default
  pattern; không được dùng để thử mật khẩu, crack handshake, hoặc brute-force
  WPS PIN.
- Với tác vụ phân tích nặng, ưu tiên viết ở Python trước; khi có phần nóng, ổn
  định và deterministic thì chuyển xuống `wifi-core` rồi expose qua `wifi-ffi`.
- Thay đổi schema nên tương thích ngược nếu có thể. Field mới nên optional và
  phải lưu được trong Parquet.
- CLI nên giữ command ngắn, rõ nghĩa, và ổn định; các workflow dài nên được
  gom thành subcommand thay vì yêu cầu người dùng tự nối nhiều lệnh.

## Ghi Chú Thực Tế

- Dữ liệu scan đã lưu có thể thay đổi schema theo thời gian. Khi đọc lại lịch sử
  từ `data/raw/`, loader cần ưu tiên ghép theo tên cột thay vì theo vị trí cột.
- Report và security audit nên hiển thị `location` và `evidence` để người dùng
  thấy rõ điểm yếu nằm ở đâu mà không phải mở JSON thô.
- Nếu backend native chưa sẵn sàng, Python fallback vẫn phải chạy được để người
  dùng không bị chặn ở luồng phân tích cơ bản.

