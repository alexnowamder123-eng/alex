# Đề tài 10 — DevSecOps Cisco IOS & Docker

## 1. Mục tiêu và kiến trúc
Commit → GitHub Actions → (Python IOS audit + Gitleaks + Docker build/Trivy) → báo cáo và security gate. Dùng tệp IOS mẫu theo lựa chọn được phép trong đề bài, không cần router thật. FastAPI là dịch vụ minh họa. Checklist 20 tiêu chí định hướng CIS, mã CIS-01…20 là mã nội bộ, không phải ID chính thức. Cần đối chiếu phiên bản benchmark theo thiết bị trước khi dùng thực tế.

## 2. Chạy trên Windows (PowerShell tại thư mục dự án)
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m unittest discover -v
python audit.py --config before_config.txt --json reports/before.json --html reports/before.html
python audit.py --config sample_running_config.txt --fail-on-noncompliant
start reports\before.html
start reports\audit_report.html
```
Python 3.12 khuyến nghị. Kiểm toán không cần thư viện ngoài. Mã thoát 1 nếu bật gate và có FAIL. Báo cáo không chứa nội dung mật khẩu. Không dùng tệp mẫu như cấu hình sản xuất; hash chỉ minh họa. Cần xác minh khóa RSA bằng `show crypto key mypubkey rsa`, phạm vi ACL, trạng thái NTP/Syslog, toàn bộ VTY thực tế và nội dung banner. Cổng ngoài được nhận diện bằng description WAN/OUTSIDE hoặc tắt giao thức toàn cục. Cấu hình mẫu yêu cầu khai báo rõ lệnh tắt dịch vụ, không suy luận mặc định IOS.

## 3. Docker và Trivy
Cài Docker Desktop (Linux containers) và Trivy CLI. Giữ Dockerfile và requirements gốc làm baseline, quét lại cùng cơ sở dữ liệu Trivy:
```powershell
docker build --pull -t devsecops-demo:before .
trivy image --scanners vuln --format json --output reports/trivy-before.json devsecops-demo:before
```
Đọc InstalledVersion/FixedVersion trong báo cáo, nâng cấp dependency có bản vá tương thích trong requirements.txt và cập nhật base image (không giả định phiên bản nào đã hết CVE). Sau đó:
```powershell
docker build --pull --no-cache -t devsecops-demo:1.0 .
trivy image --scanners vuln --format json --output reports/trivy-after.json devsecops-demo:1.0
python compare_trivy.py reports/trivy-before.json reports/trivy-after.json
trivy image --scanners vuln --severity CRITICAL --exit-code 1 devsecops-demo:1.0
docker run --rm -p 127.0.0.1:8000:8000 devsecops-demo:1.0
```
Mở http://localhost:8000/health. Dockerfile đã dùng UID 10001, không chạy root. So sánh số phát hiện, không phải số CVE duy nhất. Báo cáo gốc trong RAR có 253 phát hiện (54 HIGH,109 MEDIUM,83 LOW,7 UNKNOWN, không có CRITICAL được ghi nhận); image tên cis-audit, không chứng minh là image FastAPI hiện tại. Không có kết quả quét sau thực tế trong môi trường này.

## 4. GitHub Actions
Tạo repository mới, đưa các tệp dự án lên (không đưa .venv, config thật chứa bí mật hoặc báo cáo có secret). Workflow `.github/workflows/devsecops.yml` chạy khi push, pull request hoặc chạy thủ công. Ba job độc lập: audit + unit tests, Gitleaks, Docker/Trivy. Xem Actions → run → Artifacts. Trivy không bỏ qua CRITICAL chưa có bản vá. Gitleaks action có thể yêu cầu license với repository tổ chức; nếu gặp lỗi sử dụng CLI Gitleaks theo hướng dẫn chính thức. Không đưa token thật vào Git.

## 5. Kết quả kiểm toán mẫu
Trước: 2 PASS, 18 FAIL, 10%. Sau: 20 PASS, 0 FAIL, 100%. Tăng 90 điểm phần trăm. Đây là kết quả chạy trên hai tệp mẫu, không phải chứng nhận thiết bị thật. Sáu unit test đã chạy thành công.

## 6. Nâng cao (tùy chọn, chưa thử trên cluster)
Cài cluster Kubernetes và Kyverno tương thích với trường validate.failureAction. `kubectl create namespace devsecops-lab`, `kubectl apply -f k8s/policy.yaml`, nạp image devsecops-demo:1.0 vào cluster rồi `kubectl apply -f k8s/pod.yaml`. Thử đổi tag thành latest, bỏ limits hoặc runAsNonRoot: true để thấy bị từ chối. Policy minh họa chỉ kiểm tra containers thường; cần mở rộng initContainers/ephemeralContainers và runAsUser=0 để dùng sản xuất.
GitOps drift: lưu cấu hình mong muốn trong Git, thu running-config từ lab rồi chạy `python drift.py sample_running_config.txt running_config.txt`. Exit 1 khi khác, không tự ghi cấu hình. Đây là công cụ phát hiện drift thủ công, chưa có bộ thu tự động hoặc controller GitOps hoàn chỉnh. Không in cấu hình nhạy cảm ra log. Có thể đưa lệnh vào runner nội bộ theo lịch sau khi thiết lập thu cấu hình an toàn.

## 7. Tài liệu tham khảo
- https://www.cisecurity.org/cis-benchmarks
- https://trivy.dev/
- https://github.com/gitleaks/gitleaks
- https://docs.github.com/actions
- https://kyverno.io/docs/
