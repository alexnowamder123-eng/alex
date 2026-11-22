import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from html import escape

CHECKS = [
    ("CIS-01", "Có enable secret", r"(?m)^enable secret\s+\S+", "Bảo vệ chế độ đặc quyền."),
    ("CIS-02", "Không dùng enable password dạng thường", r"(?m)^enable password\s+", "Tránh dùng mật khẩu enable dạng yếu."),
    ("CIS-03", "Bật mã hóa mật khẩu trong cấu hình", r"(?m)^service password-encryption\s*$", "Mã hóa các password dạng plaintext trong cấu hình; Type 7 không phải mã hóa mạnh."),
    ("CIS-04", "Bật SSH", r"(?m)^ip ssh version 2\s*$", "Ưu tiên SSH phiên bản 2."),
    ("CIS-05", "Có domain name", r"(?m)^ip domain-name\s+\S+", "Điều kiện hỗ trợ tạo khóa RSA cho SSH."),
    ("CIS-06", "Có khóa RSA", r"(?m)^crypto key generate rsa|^crypto pki trustpoint", "Cần kiểm tra khóa RSA thực tế trên thiết bị."),
    ("CIS-07", "Có username local dùng secret", r"(?m)^username\s+\S+.*\bsecret\b", "Dùng secret thay cho password dạng thường."),
    ("CIS-08", "VTY dùng SSH", r"(?ms)^line vty[^\n]*\n(?:(?!^line ).*\n)*?\s*transport input\s+ssh\b", "Không cho phép Telnet trên VTY."),
    ("CIS-09", "VTY có login local hoặc AAA", r"(?ms)^line vty[^\n]*\n(?:(?!^line ).*\n)*?\s*(login local|login authentication)\b", "Yêu cầu xác thực khi truy cập từ xa."),
    ("CIS-10", "Có ACL quản lý", r"(?m)^ip access-list (standard|extended)\s+\S+|^access-list\s+\d+", "Tạo ACL để giới hạn truy cập."),
    ("CIS-11", "Có AAA new-model", r"(?m)^aaa new-model\s*$", "Bật khung AAA."),
    ("CIS-12", "Có cấu hình Syslog", r"(?m)^logging host\s+\S+|^logging\s+\d{1,3}(?:\.\d{1,3}){3}", "Gửi log đến máy chủ tập trung."),
    ("CIS-13", "Có cấu hình NTP", r"(?m)^ntp server\s+\S+", "Đồng bộ thời gian."),
    ("CIS-14", "Có banner cảnh báo", r"(?m)^banner (motd|login|exec)\s+\S+", "Hiển thị cảnh báo khi truy cập."),
    ("CIS-15", "Tắt HTTP server", r"(?m)^no ip http server\s*$", "Tắt dịch vụ HTTP quản trị không mã hóa."),
    ("CIS-16", "Tắt HTTPS server nếu không sử dụng", r"(?m)^no ip http secure-server\s*$", "Tắt giao diện HTTPS nếu không có nhu cầu."),
    ("CIS-17", "Có timeout cho VTY", r"(?ms)^line vty[^\n]*\n(?:(?!^line ).*\n)*?\s*exec-timeout\s+[1-9]\d*\s+\d+", "Tự động ngắt phiên nhàn rỗi."),
    ("CIS-18", "Có giới hạn số lần đăng nhập", r"(?m)^login block-for\s+\d+", "Giảm nguy cơ dò mật khẩu."),
    ("CIS-19", "Có cấu hình ACL áp dụng trên interface", r"(?m)^\s*(ip access-group|ipv6 traffic-filter)\s+\S+", "Lọc lưu lượng vào/ra interface."),
    ("CIS-20", "Có cấu hình logging buffered", r"(?m)^logging buffered\s+\d+", "Lưu log cục bộ để hỗ trợ kiểm tra.")
]

def audit(config_text):
    results = []
    for code, title, pattern, reason in CHECKS:
        matched = re.search(pattern, config_text, re.IGNORECASE) is not None
        # CIS-02 yêu cầu KHÔNG tồn tại lệnh enable password dạng thường.
        passed = (not matched) if code == "CIS-02" else matched
        results.append({
            "id": code,
            "criterion": title,
            "status": "PASS" if passed else "FAIL",
            "reason": reason
        })
    total = len(results)
    passed = sum(item["status"] == "PASS" for item in results)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_checks": total,
        "passed": passed,
        "failed": total - passed,
        "compliance_percent": round(passed * 100 / total, 2) if total else 0,
        "results": results
    }

def write_html(report, output_path):
    rows = []
    for item in report["results"]:
        status_class = "pass" if item["status"] == "PASS" else "fail"
        rows.append(
            f"<tr><td>{escape(item['id'])}</td>"
            f"<td>{escape(item['criterion'])}</td>"
            f"<td class='{status_class}'>{escape(item['status'])}</td>"
            f"<td>{escape(item['reason'])}</td></tr>"
        )
    html = f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8">
<title>Báo cáo CIS Audit</title>
<style>
body{{font-family:Arial,sans-serif;margin:32px;color:#222}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:9px;text-align:left}}
th{{background:#eee}} .pass{{color:green;font-weight:bold}}
.fail{{color:#c00;font-weight:bold}}
.summary{{padding:14px;background:#f3f6fa;margin:16px 0}}
</style></head><body>
<h1>Báo cáo kiểm toán cấu hình Cisco IOS</h1>
<div class="summary">
<p>Tổng tiêu chí: {report['total_checks']}</p>
<p>Đạt: {report['passed']} | Chưa đạt: {report['failed']}</p>
<h2>Tỷ lệ tuân thủ: {report['compliance_percent']}%</h2>
<p>Thời gian: {escape(report['generated_at'])}</p>
</div>
<table><thead><tr><th>Mã</th><th>Tiêu chí</th><th>Kết quả</th><th>Ý nghĩa</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p><i>Lưu ý: Đây là checklist thực hành định hướng CIS, không phải chứng nhận CIS chính thức.
Cần hiệu chỉnh theo model và phiên bản Cisco IOS cụ thể.</i></p>
</body></html>"""
    Path(output_path).write_text(html, encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="Cisco IOS configuration audit")
    parser.add_argument("--config", default="sample_running_config.txt")
    parser.add_argument("--json", default="reports/audit_report.json")
    parser.add_argument("--html", default="reports/audit_report.html")
    parser.add_argument("--fail-on-noncompliant", action="store_true")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        raise SystemExit(f"Không tìm thấy file cấu hình: {config_path}")

    report = audit(config_path.read_text(encoding="utf-8", errors="ignore"))
    json_path, html_path = Path(args.json), Path(args.html)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(report, html_path)

    print(f"Tổng tiêu chí: {report['total_checks']}")
    print(f"Đạt: {report['passed']} | Chưa đạt: {report['failed']}")
    print(f"Tỷ lệ tuân thủ: {report['compliance_percent']}%")
    print(f"Đã xuất: {json_path} và {html_path}")

    if args.fail_on_noncompliant and report["failed"] > 0:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
