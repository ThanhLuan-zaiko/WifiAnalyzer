# Hướng Dẫn Sử Dụng Nzig

Tài liệu này giải thích các màn hình trong ảnh theo đúng luồng lệnh bạn đã
chạy. Mục tiêu là giúp đọc kết quả nhanh, hiểu chỗ nào là điểm yếu của mạng,
và biết nên làm gì tiếp theo.

## 1. `nzig doctor`

Lệnh này kiểm tra môi trường chạy của dự án.

### Ý nghĩa các dòng

- `scanner`: backend quét WiFi hiện tại. Nếu hiện `ok`, hệ điều hành và adapter
  quét đã sẵn sàng.
- `cargo`: toolchain Rust.
- `uv`: trình quản lý môi trường Python.
- `python`: phiên bản Python đang dùng.
- `duckdb`, `polars`, `sklearn`: thư viện Python phục vụ lưu trữ, xử lý dữ
  liệu, và mô hình hóa.
- `native_backend`: cho biết backend native đã build và sẵn sàng chưa.

### Cách đọc nhanh

Nếu tất cả đều `ok`, máy đã đủ điều kiện để quét, lưu lịch sử, và phân tích.
Nếu dòng nào `fail` hoặc `warn`, hãy sửa đúng thành phần đó trước khi chạy scan
thật.

## 2. `nzig scan --mock`

Lệnh này tạo dữ liệu mẫu để kiểm tra luồng hiển thị mà không cần quét phần
cứng.

### Cột trong bảng

- `SSID`: tên mạng.
- `BSSID`: địa chỉ MAC của access point.
- `Band`: băng tần, ví dụ `2.4` hoặc `5`.
- `Ch`: kênh WiFi.
- `Freq`: tần số MHz.
- `RSSI`: cường độ tín hiệu, số càng gần 0 thường là càng mạnh.
- `Security`: kiểu bảo mật được công bố.

### Ý nghĩa trong ảnh

Trong ảnh của bạn, các dòng `Cafe-Lab`, `Office`, `Printer`, `Mesh-5G` là dữ
liệu giả lập để kiểm tra table hiển thị. Chúng cho thấy:

- mạng `Office` đang ở chế độ `WPA2/WPA3` transition mode
- các mạng `Mesh-5G` dùng `WPA3`
- `Cafe-Lab` và `Printer` dùng `WPA2`

Đây là dữ liệu minh họa để xem layout, không phải kết luận bảo mật thật.

## 3. `nzig scan --save`

Lệnh này quét rồi lưu kết quả vào storage nội bộ.

### Điều gì xảy ra

- file Parquet được ghi vào `data/raw/date=YYYY-MM-DD/`
- DuckDB catalog được cập nhật ở `data/wifi.duckdb`
- output JSON phía trên cho biết:
  - `scan_id`
  - `parquet_path`
  - `duckdb_path`
  - số lượng `records`

### Ý nghĩa trong ảnh

Ảnh cho thấy `records: 4`, tức là 4 access point đã được lưu trong lần quét
đó. Đây là bước chuẩn bị để sau này audit lại hoặc tạo report.

## 4. `nzig analyze channels --band 2.4 --top 3 --live`

Lệnh này phân tích kênh 2.4 GHz và đề xuất kênh ít nhiễu hơn.

### Các cột

- `Band`: băng tần đang phân tích.
- `Ch`: kênh đề xuất.
- `Freq`: tần số tương ứng.
- `Score`: điểm càng cao thì càng đáng ưu tiên.
- `Interference`: mức giao thoa ước tính.
- `APs`: số access point chồng lấp với kênh đó.
- `Strong`: số access point tín hiệu mạnh trong vùng đó.
- `Reason`: giải thích ngắn.

### Ý nghĩa trong ảnh

Kết quả gợi ý `1`, `11`, và `6` là các kênh đáng xem xét nhất trong ảnh.
Điều này có nghĩa:

- kênh `1` đang sạch hơn so với nhiều kênh khác
- kênh `11` cũng khá ổn
- kênh `6` có giao thoa cao hơn nên xếp sau

Mục đích là chọn kênh giúp mạng ổn định hơn, không phải khai thác mạng khác.

## 5. `nzig analyze security --live --mock`

Đây là màn hình quan trọng nhất để nhìn ra WiFi yếu ở đâu.

### Các cột

- `Severity`: mức độ nghiêm trọng.
- `Score`: điểm rủi ro tổng hợp.
- `SSID`: tên mạng.
- `BSSID`: MAC của access point.
- `Location`: điểm yếu nằm ở lớp nào.
- `Evidence`: bằng chứng thụ động đã kích hoạt cảnh báo.
- `Security`: chế độ bảo mật quảng bá.
- `Findings`: tên các cảnh báo áp dụng cho dòng đó.

### Cách đọc `Location`

- `link-layer encryption`: yếu ở lớp mã hóa, ví dụ open/WEP/WPA cũ.
- `security mode`: yếu ở cấu hình WPA2/WPA3 hoặc thiếu thông tin bảo mật.
- `SSID naming`: yếu ở tên mạng, thường là mặc định hoặc khớp marker rủi ro.
- `router management metadata`: yếu ở WPS.
- `protected management frames metadata`: yếu ở PMF/802.11w.

### Ý nghĩa trong ảnh

Trong ảnh, các dòng như:

- `Office` có `WPA2/WPA3 transition mode`
- `Cafe-Lab` có `WPA2 network`
- `Mesh-5G` có `WPA3 network`

đều cho biết vị trí bảo mật khác nhau:

- `Office` yếu ở `security mode` vì transition mode có thể kém chặt hơn
  WPA3-only
- `Cafe-Lab` và `Printer` yếu ở `security mode` vì chỉ là WPA2
- `Mesh-5G` là WPA3 nên tốt hơn, nhưng vẫn nên giữ firmware cập nhật

Khi `Location` trống trong ảnh cũ, đó là vì lúc trước output chưa đẩy trường
này lên cấp row. Hiện tại đã sửa để hiện rõ.

## 6. `nzig analyze security --wordlist internal-risk-markers.txt`

Lệnh này dùng danh sách marker phòng thủ để phát hiện SSID kiểu mặc định hoặc
kiểu đặt tên giống nhà sản xuất/ISP.

### Cách dùng đúng

- chỉ dùng để audit
- không dùng để thử mật khẩu
- không dùng để tấn công WPS
- không dùng để bẻ handshake

### Khi nào hữu ích

Nếu SSID giống kiểu:

- `TP-Link_1234`
- `VIETTEL_...`
- `NETGEAR...`

thì đó là dấu hiệu nên kiểm tra lại router, đổi SSID, và xác nhận passphrase
là duy nhất.

## 7. Tài Liệu Cần Đọc Kèm

- [docs/SECURITY_AUDIT.md](SECURITY_AUDIT.md): giải thích chi tiết từng finding
  bảo mật.
- [docs/ARCHITECTURE.md](ARCHITECTURE.md): mô tả kiến trúc module và luồng dữ
  liệu.

## 8. Tóm Tắt Ngắn

Nếu chỉ nhớ một điều thì là:

- `doctor` kiểm tra môi trường
- `scan` xem mạng
- `scan --save` lưu lịch sử
- `analyze channels` chọn kênh sạch hơn
- `analyze security` chỉ ra điểm yếu của WiFi nằm ở đâu

