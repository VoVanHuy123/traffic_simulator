# traffic_simulator — Cursor

Tài liệu gộp ngữ cảnh dự án và nội dung quan trọng để trợ lý làm việc trong repo này.

---

## Dự án

**Luồng chính:** PCAP → tiền xử lý → trích dataset flow/sequences → huấn luyện model → sinh traffic tổng hợp → đánh giá.

| Tầng | Nội dung | Vị trí chính |
|------|----------|-------------|
| Preprocessing | Đọc PCAP, phân loại protocol, build flow, extract features | `preprocessing/`, `preprocessing/protocols/`, `preprocessing/packet_parser.py`, `preprocessing/extractor.py` |
| Dataset | Lưu CSV flow và sequence theo protocol | `dataset/`, `preprocessing/dataset_exporter.py` |
| Training | Flow model dùng copulas; sequence model dùng HMM | `training/flow_training.py`, `training/sequences_training.py` |
| Generation | Sinh feature, decode sequence, tạo PCAP | `generation/`, `generation/base_generator.py`, `generation/generator.py` |
| Evaluation | So sánh traffic tổng hợp với dữ liệu thật | `evaluator/evaluator.py`, `evaluator/output/` |

**Thư mục quan trọng:**
- `preprocessing/` — ánh xạ packet → flow → features
- `rules/protocol_rules.py` — định nghĩa cấu trúc feature/flow cho từng protocol
- `dataset/` — chứa output dataset protocol
- `models/` — chứa model flow & sequence đã huấn luyện
- `generation/` — sinh dữ liệu từ model
- `evaluator/` — đánh giá chất lượng synthetic traffic

**Công nghệ chính:** Python 3, pandas, numpy, copulas, hmmlearn, scapy, joblib.

---

## Công việc mới hoàn thành

- Thêm support ISUP vào pipeline preprocessing
- Cập nhật `rules/protocol_rules.py` để có cấu hình protocol `isup`
- Tạo `ISUPHandler` trong `preprocessing/protocols/isup.py`
- Mở rộng `preprocessing/packet_parser.py` để parse trường ISUP
- Đăng ký `ISUPHandler()` trong `preprocessing/__init__.py`
- Chỉnh `preprocessing/extractor.py` để xuất `flow_id` trong flow CSV
- Đảm bảo cấu trúc flow dataset: `flow_id,packet_count,flow_duration,avg_packet_size,iat_mean,total_bytes`
- Đảm bảo cấu trúc sequence dataset: `flow_id,isup_msg_type,direction,packet_length,iat`

---

## Ghi chú khi sửa code

- Thay đổi chỉ ở phần liên quan đến protocol / feature extraction / dataset contract.
- Với dataset flow/sequence, giữ header và thứ tự trường đúng như định nghĩa trong `rules/protocol_rules.py`.
- Nếu thay đổi feature model, kiểm tra lại toàn bộ pipeline huấn luyện/sinh/đánh giá.


