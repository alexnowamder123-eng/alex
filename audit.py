import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from html import escape

def audit(config_text):
    # Chỉ xét lệnh cấp global và các block con tương ứng.
    lines = config_text.splitlines()
    globals_ = []
    blocks = {}
    current = None
    for line in lines:
        if not line.strip() or line.strip().startswith('!'):
            current = None
            continue
        if not line[0].isspace():
            current = line.strip().lower()
            globals_.append(current)
            blocks.setdefault(current, [])
        elif current:
            blocks[current].append(line.strip().lower())
    def g(pattern):
        return any(re.fullmatch(pattern, line) for line in globals_)
    vtys = [v for k,v in blocks.items() if k.startswith('line vty ')]
    def all_vty(pattern):
        return bool(vtys) and all(any(re.fullmatch(pattern,x) for x in v) for v in vtys)
    acl_names = {k.split()[-1] for k,v in blocks.items() if re.fullmatch(r'ip access-list (standard|extended) \S+',k) and any(x.startswith('permit ') for x in v)}
    acl_names.update(m.group(1) for x in globals_ if (m:=re.fullmatch(r'access-list (\d+) permit .+',x)))
    def acl_ok(v):
        return any((m:=re.fullmatch(r'access-class (\S+) in(?: vrf-also)?',x)) and m.group(1) in acl_names for x in v)
    # Phạm vi lab: interface có description chứa OUTSIDE hoặc WAN.
    outside = [v for k,v in blocks.items() if k.startswith('interface ') and any(re.search(r'^description .*\b(outside|wan)\b',x) for x in v)]
    def outside_off(protocol):
        return g('no '+protocol+' run') or (bool(outside) and all((('no cdp enable' in v) if protocol=='cdp' else ('no lldp transmit' in v and 'no lldp receive' in v)) for v in outside))
    checks = [
        ('Enable secret', g(r'enable secret (?:[589] )?\S+.*'), 'Dùng enable secret; ưu tiên type 8/9 nếu hỗ trợ.'),
        ('Không có enable password', not g(r'enable password .+'), 'Loại bỏ enable password.'),
        ('Service password-encryption', g('service password-encryption'), 'Type 7 chỉ che giấu, không phải mã hóa mạnh.'),
        ('SSH version 2', g('ip ssh version 2'), 'Chỉ sử dụng SSH v2.'),
        ('Domain name', g(r'ip domain[- ]name \S+'), 'Hỗ trợ cấu hình SSH.'),
        ('Tắt CDP cổng ngoài', outside_off('cdp'), 'Tắt CDP toàn cục hoặc mọi cổng WAN/OUTSIDE.'),
        ('Username local dùng secret', g(r'username \S+.* secret (?:[589] )?\S+.*') and not g(r'username \S+.* password .+'), 'Không dùng username password.'),
        ('Mọi VTY chỉ nhận SSH', all_vty('transport input ssh'), 'Không cho phép Telnet hoặc transport all.'),
        ('Mọi VTY xác thực', all_vty(r'login local|login authentication \S+'), 'Kiểm tra cấu hình xác thực; AAA method list cần xác minh thêm.'),
        ('Mọi VTY có ACL inbound tồn tại', bool(vtys) and all(acl_ok(v) for v in vtys), 'ACL phải tồn tại và được gắn vào VTY; phạm vi permit cần duyệt thủ công.'),
        ('AAA new-model', g('aaa new-model'), 'Bật AAA.'),
        ('Syslog tập trung', g(r'logging (?:host )?(?:\d{1,3}\.){3}\d{1,3}(?: .*)?') or g(r'logging host \S+.*'), 'Cấu hình máy chủ log.'),
        ('NTP server', g(r'ntp server \S+.*'), 'Cấu hình đồng bộ thời gian.'),
        ('Banner cảnh báo', g(r'banner (?:motd|login|exec) \S+.*'), 'Cần duyệt nội dung banner thủ công.'),
        ('Tắt HTTP', g('no ip http server') and not g('ip http server'), 'Tắt HTTP không mã hóa.'),
        ('Tắt HTTPS không sử dụng', g('no ip http secure-server') and not g('ip http secure-server'), 'Chính sách lab: không dùng web quản trị.'),
        ('Timeout mọi VTY tối đa 5 phút', bool(vtys) and all(any((m:=re.fullmatch(r'exec-timeout (\d+) (\d+)',x)) and 0 < int(m.group(1))*60+int(m.group(2)) <= 300 for x in v) for v in vtys), 'Không để phiên nhàn rỗi vô hạn.'),
        ('Giới hạn đăng nhập', g(r'login block-for [1-9]\d* attempts [1-9]\d* within [1-9]\d*'), 'Giảm dò mật khẩu.'),
        ('Tắt LLDP cổng ngoài', outside_off('lldp'), 'Tắt LLDP toàn cục hoặc transmit/receive trên mọi cổng ngoài.'),
        ('Logging buffered', g(r'logging buffered [1-9]\d*(?: .*)?'), 'Lưu log cục bộ.')]
    results = [{'id':f'CIS-{i:02}', 'criterion':title, 'status':'PASS' if ok else 'FAIL', 'reason':reason} for i,(title,ok,reason) in enumerate(checks,1)]
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

    config = config_path.read_text(encoding="utf-8-sig")
    if not re.search(r"(?m)^hostname\s+\S+", config):
        raise SystemExit("File không có hostname IOS; kiểm tra đầu vào.")
    report = audit(config)
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
