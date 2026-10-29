# 🩺 NetDoctor — Agent LangGraph chẩn đoán & sửa chữa hệ thống mạng/VM

NetDoctor là agent **LangGraph** tự động:

1. **SSH** vào máy ảo / host mạng (paramiko) để thu thập số liệu hệ thống (read-only)
2. **Phân tích log** hệ thống (`journalctl`, `auth.log`, `syslog`, `dmesg`) bằng rule-based + LLM
3. **Chẩn đoán** sự cố (disk đầy, service chết, link down, OOM, brute-force SSH, ...)
4. **Lập kế hoạch sửa chữa** an toàn, chờ **con người phê duyệt** (human-in-the-loop)
5. **Thực thi** từng bước, **kiểm tra lại** sau sửa và sinh **báo cáo Markdown**

```
┌──────────────┐   ┌──────────────┐   ┌───────────┐
│collect_facts │ → │ collect_logs │ → │ diagnose  │
└──────────────┘   └──────────────┘   └─────┬─────┘
                                            │
        ┌───────────────────────────────────┼──────────────────────┐
        │ cần thêm info (loop có giới hạn) │ có lỗi & --remediate │ không / ổn
        ▼                                   ▼                      ▼
  collect_logs ──► plan ──► approval(interrupt) ──► execute ──► verify ──► report ──► END
```

## Cài đặt

```bash
cd ~/Desktop/langgraph
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env          # điền API key nếu muốn dùng LLM
```

Không có API key? Agent vẫn chạy được ở chế độ **heuristic (offline)** với bộ rule có sẵn.

## Cấu hình host

Sửa `configs/hosts.yaml`:

```yaml
defaults:
  port: 22
  sudo: false
hosts:
  - name: vm-web-01
    host: 192.168.122.10
    username: admin
    auth: key              # password | key | none
    key_file: ~/.ssh/id_ed25519
    tags: [web, production]
```

Biến môi trường (`.env`):

| Biến | Mô tả |
|---|---|
| `NETDOCTOR_LLM_API_KEY` | API key (OpenAI-compatible: OpenAI, DeepSeek, vLLM, Ollama...) |
| `NETDOCTOR_LLM_MODEL` | Tên model, mặc định `gpt-4o-mini` |
| `NETDOCTOR_LLM_BASE_URL` | URL server LLM (tuỳ chọn) |
| `NETDOCTOR_HOSTS_FILE` | Đường dẫn hosts.yaml |
| `NETDOCTOR_REPORTS_DIR` | Thư mục lưu báo cáo |
| `NETDOCTOR_COMMAND_DELAY` | Delay (giây) giữa các lệnh SSH |

## Sử dụng

```bash
# Liệt kê host
.venv/bin/python main.py list-hosts

# Chẩn đoán + sửa chữa (có hỏi xác nhận trước khi chạy kế hoạch)
.venv/bin/python main.py run --host vm-web-01 --remediate

# Chạy tự động không cần xác nhận (chỉ dùng khi bạn tin vào kế hoạch)
.venv/bin/python main.py run --host vm-web-01 --remediate --auto-approve

# Chỉ chẩn đoán, không sửa
.venv/bin/python main.py run --host vm-web-01

# Chỉ phân tích log
.venv/bin/python main.py logs --host vm-web-01

# Chế độ offline (không cần API key) + host giả lập để demo
.venv/bin/python main.py run --host mock-demo --remediate --auto-approve --offline
```

Host `mock-demo` có sẵn trong `hosts.yaml`: mô phỏng VM gặp disk đầy 94%,
eth1 DOWN, nginx failed và brute-force SSH — dùng để trải nghiệm toàn bộ
luồng mà **không cần máy thật**.

Báo cáo được lưu tại `logs/reports/<tên-host>.md`.

## Kiểm soát an toàn (quan trọng)

Mọi lệnh trước khi chạy đều qua bộ lọc `netdoctor/safety.py`:

- **CRITICAL — bị chặn vĩnh viễn**: `rm -rf /`, `mkfs`, `dd of=/dev/*`, `iptables -F`,
  `shutdown/reboot`, `wipefs`, fork bomb, ghi đè `/etc/passwd`...
- **HIGH**: `systemctl restart/stop`, `swapoff`, `apt remove`... — chỉ chạy khi được phê duyệt
- **MEDIUM**: `journalctl --vacuum`, `apt-get clean`, `ip link set up`, `ufw`...
- **LOW**: các lệnh read-only (`df`, `free`, `ip a`, `journalctl`, `ping`...)

Nguyên tắc:

- Giai đoạn **chẩn đoán chỉ chạy lệnh read-only** — không sửa gì trên host
- Kế hoạch sửa chữa **luôn dừng ở bước phê duyệt** (`interrupt()` của LangGraph),
  trừ khi truyền `--auto-approve`
- Thực thi **tuần tự**, dừng khi một bước fail (trừ khi bước đó `continue_on_error`)
- Có **delay** giữa các lệnh SSH (`NETDOCTOR_COMMAND_DELAY`) để không làm nghẽn host
- SSH tự **retry** khi kết nối lỗi, mọi lỗi đều được ghi nhận vào báo cáo

## Kiến trúc mã

```
main.py                    # CLI (rich)
configs/hosts.yaml         # danh sách host/VM
netdoctor/
├── config.py              # Settings (pydantic-settings) + HostEntry
├── state.py               # AgentState + schema (Diagnosis, RepairPlan, ...)
├── ssh_client.py          # SSHSession (paramiko) + HostClient protocol
├── mock_host.py           # host giả lập cho demo/test
├── safety.py              # chặn lệnh nguy hiểm + phân loại rủi ro
├── heuristics.py          # parse df/free/systemctl/ip + trích tín hiệu log
├── analyzers.py           # heuristic_diagnose + heuristic_plan
├── llm.py                 # nhà máy LLM OpenAI-compatible (fallback heuristic)
├── nodes.py               # các node của graph
└── graph.py               # StateGraph + conditional edges
tests/                     # pytest: safety, ssh (mock paramiko), graph e2e
```

## Chạy test

```bash
.venv/bin/python -m pytest tests/ -q
```

- `test_safety.py` — lệnh nguy hiểm bị chặn, phân loại rủi ro đúng
- `test_ssh_client.py` — SSHSession với paramiko giả lập (retry, sudo, chặn lệnh)
- `test_graph.py` — chạy full graph với host mock: chẩn đoán → sửa → verify đạt,
  và luồng human-approval bằng `interrupt()`

## Lưu ý

- Agent chỉ nên chạy trên host mà bạn có quyền quản trị. Đọc kỹ kế hoạch trước khi phê duyệt.
- Chế độ `--auto-approve` phù hợp cho môi trường demo/lab, **không** khuyến khích production.
- Nếu host dùng `sudo: true`, tài khoản cần cấu hình NOPASSWD cho các lệnh cần quyền.
