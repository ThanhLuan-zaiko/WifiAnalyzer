# Hướng Dẫn Kiểm Tra Bảo Mật WiFi

Tài liệu này giải thích cách Nzig báo cáo tình trạng bảo mật WiFi từ metadata
quét thụ động בלבד. Tài liệu không mô tả và cũng không hỗ trợ bẻ mật khẩu,
bắt handshake, deauth, hay brute-force WPS.

## Phạm Vi

Nzig kiểm tra metadata access point mà hệ điều hành đã cung cấp sẵn. Dữ liệu
đầu vào thường là:

- `SSID`
- `BSSID`
- chế độ bảo mật được quảng bá
- gợi ý về `PMF` / `WPS`
- `RSSI`
- các trường quét khác

Nzig không cần mật khẩu, không cần handshake, và không cần probe chủ động để
tạo ra các cảnh báo bên dưới.

## Lệnh Liên Quan

```powershell
nzig analyze security
nzig analyze security --live
nzig analyze security --live --mock
nzig analyze security --wordlist internal-risk-markers.txt
```

Tùy chọn `--wordlist` chỉ dùng cho mục đích phòng thủ. Nó nạp các marker thụ
động để nhận diện SSID kiểu mặc định hoặc mẫu đặt tên của hãng/ISP. Các từ này
không bao giờ được dùng như mật khẩu và không bao giờ được thử trên mạng.

## Trường Kết Quả

Mỗi dòng audit có các trường sau:

- `severity`: mức độ nghiêm trọng.
- `risk_score`: điểm rủi ro từ 0 đến 100.
- `location`: phần cấu hình nơi vấn đề xuất hiện.
- `evidence`: dữ liệu thụ động dùng để kết luận.
- `source`: kiểu metadata đã tạo ra cảnh báo.
- `findings`: danh sách tiêu đề cảnh báo dễ đọc.
- `recommendations`: hướng xử lý tương ứng.
- `password_risk`: ghi chú phòng thủ về việc có suy ra rủi ro mật khẩu hay không.

CLI và report Markdown đều hiển thị `location` và `evidence` để bạn nhìn ra
điểm yếu mà không cần mở JSON.

## Cách Đọc `location`

Hãy xem `location` như câu trả lời đầu tiên cho câu hỏi: "WiFi này yếu ở đâu?"

- `link-layer encryption`: kiểu mã hóa công bố là mở, cũ, hoặc lỗi thời.
- `security mode`: metadata cho thấy WPA2, WPA3, transition mode, hoặc thiếu
  thông tin bảo mật.
- `SSID naming`: tên mạng khớp mẫu mặc định hoặc marker rủi ro được cung cấp.
- `router management metadata`: metadata thụ động cho thấy WPS.
- `protected management frames metadata`: metadata thụ động cho thấy PMF/802.11w
  đang tắt hoặc chỉ ở chế độ tùy chọn.

`evidence` là bằng chứng đi kèm. Ví dụ:

- `security='open'`
- `ssid='TP-Link_1234'`
- `raw={'wps': {'enabled': True}}`

## Danh Mục Cảnh Báo

| Mã cảnh báo | Vị trí | Ý nghĩa | Hành động khuyến nghị |
| --- | --- | --- | --- |
| `open_network` | `link-layer encryption` | AP công bố không có mã hóa lớp liên kết. | Bật WPA3-Personal hoặc WPA2-AES với mật khẩu riêng. |
| `wep` | `link-layer encryption` | WEP đang được quảng bá. | Thay bằng WPA3-Personal hoặc WPA2-AES. |
| `wpa1` | `link-layer encryption` | Mạng đang dùng WPA/TKIP kiểu cũ. | Tắt tương thích WPA/WPA1. |
| `tkip` | `cipher suite` | Cấu hình có TKIP. | Chỉ dùng AES/CCMP. |
| `security_unknown` | `security field` | Quét không thấy rõ kiểu mã hóa. | Kiểm tra router và xác nhận WPA3 hoặc WPA2-AES. |
| `encryption_details_unavailable` | `security field` | Hệ thống chỉ báo "secured" nhưng không cho biết mode/cipher. | Kiểm tra lại chế độ WPA và cipher trên router. |
| `wpa2` | `security mode` | Mạng đang ở WPA2. | Ưu tiên WPA3 nếu tất cả client hỗ trợ. |
| `transition_mode` | `security mode` | WPA2/WPA3 transition mode đang bật. | Dùng WPA3-only nếu có thể. |
| `wpa3` | `security mode` | Mạng đang ở WPA3. | Giữ firmware cập nhật và dùng mật khẩu riêng. |
| `hidden_ssid` | `SSID broadcast behavior` | SSID bị ẩn. | Không nên dựa vào việc ẩn SSID như một biện pháp bảo mật chính. |
| `default_like_ssid` | `SSID naming` | Tên mạng giống mặc định của hãng hoặc ISP. | Đổi SSID và xác nhận mật khẩu là duy nhất. |
| `wordlist_ssid_marker` | `SSID naming` | SSID khớp marker rủi ro thụ động. | Xác nhận tên mạng và mật khẩu không còn là mặc định. |
| `wps_advertised` | `router management metadata` | Metadata cho thấy WPS có thể đang bật. | Tắt WPS, đặc biệt là WPS PIN. |
| `pmf_disabled` | `protected management frames metadata` | PMF/802.11w có vẻ đang tắt. | Bật PMF nếu client còn tương thích. |
| `pmf_optional` | `protected management frames metadata` | PMF/802.11w chỉ ở chế độ tùy chọn. | Chuyển sang bắt buộc PMF trên mạng hỗ trợ WPA3. |

## Cách Hiểu `password_risk`

`password_risk` được thiết kế rất thận trọng.

- `not_applicable`: mạng mở, nên không áp dụng khái niệm độ mạnh mật khẩu.
- `possible_default_or_weak`: SSID trông giống mặc định hoặc khớp marker thụ
  động, nhưng Nzig không hề kiểm tra mật khẩu.
- `unknown`: metadata không đủ để suy ra mật khẩu mạnh hay yếu.

## Quy Trình Đọc Kết Quả

1. Chạy `nzig analyze security --live` trên mạng đã được phép kiểm tra.
2. Xem dòng có `severity` cao nhất trước.
3. Đọc `location` để biết điểm yếu nằm ở đâu.
4. Đọc `evidence` để biết dữ kiện nào dẫn tới cảnh báo.
5. Áp dụng `recommendations`.
6. Chạy lại audit sau khi đổi cấu hình router.

## Ghi Chú

- Ẩn SSID không phải là biện pháp bảo mật thực sự.
- SSID kiểu mặc định chỉ là dấu hiệu cảnh báo, không phải bằng chứng đã bị xâm
  nhập.
- Audit này là danh sách hardening thụ động, không phải phép đo mật khẩu.

