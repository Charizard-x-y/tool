"""
poc生成验证工具
作者：Charizard_xy
最后更新：2025.02.27
"""
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import threading
import json
from urllib.parse import urlparse

class VulnerabilityScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("漏洞验证工具 v1.0")
        master.geometry("1000x800")

        # 初始化变量
        self.parsed_request = {}
        self.url_list = []
        self.proxy_list = []
        self.current_proxy_idx = 0
        self.scan_results = []
        self.proxy_enabled = tk.BooleanVar(value=True)

        # 创建界面组件
        self.create_widgets()

    def create_widgets(self):
        # 请求解析部分
        request_frame = ttk.LabelFrame(self.master, text="HTTP请求解析")
        request_frame.pack(fill=tk.X, padx=10, pady=5)

        self.raw_request_text = scrolledtext.ScrolledText(request_frame, height=10)
        self.raw_request_text.pack(fill=tk.X, padx=5, pady=5)

        parse_btn = ttk.Button(request_frame, text="解析请求", command=self.parse_request)
        parse_btn.pack(pady=5)

        # POC生成部分
        poc_frame = ttk.LabelFrame(self.master, text="POC生成")
        poc_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.poc_text = scrolledtext.ScrolledText(poc_frame)
        self.poc_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 批量验证部分
        batch_frame = ttk.LabelFrame(self.master, text="批量验证")
        batch_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(batch_frame, text="导入URL列表", command=self.load_urls).pack(side=tk.LEFT, padx=5)
        ttk.Button(batch_frame, text="开始扫描", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(batch_frame, text="导出报告", command=self.export_report).pack(side=tk.LEFT, padx=5)

        # 代理管理部分
        proxy_frame = ttk.LabelFrame(self.master, text="代理管理")
        proxy_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(proxy_frame, text="获取最新代理", command=self.fetch_proxies).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(proxy_frame, text="启用代理", variable=self.proxy_enabled).pack(side=tk.LEFT, padx=5)
        self.proxy_status = ttk.Label(proxy_frame, text="可用代理：0")
        self.proxy_status.pack(side=tk.LEFT, padx=5)

        # 日志输出
        log_frame = ttk.LabelFrame(self.master, text="扫描日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def parse_request(self):
        raw_text = self.raw_request_text.get("1.0", tk.END).strip()
        try:
            # 解析请求方法、路径和协议
            lines = [line.strip() for line in raw_text.split('\n') if line.strip()]
            first_line = lines[0].split()
            method, path, protocol = first_line[0], first_line[1], first_line[2]

            # 解析headers
            headers = {}
            body = ""
            for line in lines[1:]:
                if not line:
                    continue
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                else:
                    body += line + '\n'

            self.parsed_request = {
                'method': method,
                'path': path,
                'headers': headers,
                'body': body.strip()
            }

            self.generate_poc()
            self.log("请求解析成功！")
        except Exception as e:
            messagebox.showerror("解析错误", f"请求解析失败: {str(e)}")

    def generate_poc(self):
        if not self.parsed_request:
            return

        poc_template = f"""import requests

def check_vulnerability(url):
    try:
        headers = {self.parsed_request['headers']}
        data = '''{self.parsed_request['body']}'''
        
        response = requests.{self.parsed_request['method'].lower()}(
            url + "{self.parsed_request['path']}",
            headers=headers,
            data=data,
            verify=False,
            timeout=10
        )
        
        # 自定义漏洞验证逻辑
        if 'vulnerable_pattern' in response.text:
            return True, response.status_code
        return False, response.status_code
    except Exception as e:
        return False, str(e)
"""
        self.poc_text.delete("1.0", tk.END)
        self.poc_text.insert(tk.END, poc_template)
        self.log("POC生成成功！")

    def load_urls(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as f:
                self.url_list = [line.strip() for line in f if line.strip()]
            self.log(f"成功导入 {len(self.url_list)} 个URL")

    def fetch_proxies(self):
        def _fetch():
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
                response = requests.get("https://www.kuaidaili.com/free/fps/", headers=headers)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                proxies = []
                for row in soup.select('#list table tbody tr'):
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        proxies.append(f"{ip}:{port}")

                # 验证代理可用性
                valid_proxies = []
                with ThreadPoolExecutor(max_workers=20) as executor:
                    results = executor.map(lambda p: self.test_proxy(p), proxies)
                    for proxy, is_valid in zip(proxies, results):
                        if is_valid:
                            valid_proxies.append(proxy)

                self.proxy_list = valid_proxies
                self.proxy_status.config(text=f"可用代理：{len(self.proxy_list)}")
                self.log(f"成功获取 {len(self.proxy_list)} 个有效代理")
            except Exception as e:
                messagebox.showerror("代理获取失败", str(e))

        threading.Thread(target=_fetch).start()

    def test_proxy(self, proxy):
        try:
            response = requests.get(
                'http://httpbin.org/ip',
                proxies={'http': f'http://{proxy}', 'https': f'http://{proxy}'},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def get_proxy(self):
        if not self.proxy_list or not self.proxy_enabled.get():
            return None
        self.current_proxy_idx = (self.current_proxy_idx + 1) % len(self.proxy_list)
        return {'http': f'http://{self.proxy_list[self.current_proxy_idx]}',
                'https': f'http://{self.proxy_list[self.current_proxy_idx]}'}

    def start_scan(self):
        if not self.url_list:
            messagebox.showwarning("警告", "请先导入URL列表")
            return

        def _scan():
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for url in self.url_list:
                    futures.append(executor.submit(self.scan_url, url))

                for future in futures:
                    result = future.result()
                    self.scan_results.append(result)
                    self.log(f"{result['url']} - {result['status']}")

            messagebox.showinfo("完成", "扫描完成！")

        threading.Thread(target=_scan).start()

    def scan_url(self, url):
        try:
            proxies = self.get_proxy()
            
            # 构建请求
            response = requests.request(
                method=self.parsed_request.get('method', 'GET'),
                url=url + self.parsed_request.get('path', ''),
                headers=self.parsed_request.get('headers', {}),
                data=self.parsed_request.get('body', ''),
                proxies=proxies,
                timeout=10,
                verify=False
            )

            # 简单漏洞检测逻辑（需根据实际情况修改）
            is_vulnerable = 'vulnerable_pattern' in response.text
            return {
                'url': url,
                'status': '漏洞存在' if is_vulnerable else '安全',
                'status_code': response.status_code,
                'proxy': list(proxies.values())[0] if proxies else None
            }
        except Exception as e:
            return {'url': url, 'status': f'错误: {str(e)}', 'proxy': None}

    def export_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                f.write("漏洞扫描报告\n")
                f.write("="*30 + "\n")
                for result in self.scan_results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"状态: {result['status']}\n")
                    if 'status_code' in result:
                        f.write(f"状态码: {result['status_code']}\n")
                    if result['proxy']:
                        f.write(f"使用代理: {result['proxy']}\n")
                    f.write("-"*30 + "\n")
            self.log(f"报告已导出到: {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()