"""
POC自动化工具
作者：Charizard_xy
功能：HTTP请求解析 + POC自动生成 + 批量验证 + 报告导出
依赖：pip install ttkbootstrap pandas requests openpyxl
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import re
import subprocess
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap import Style

class POCGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("POC自动化")
        self.geometry("1400x800")
        Style(theme='morph').theme_use('litera')
        self._init_ui()
        self._create_toolbar()
        self._bind_events()

    def _init_ui(self):
        """构建主界面"""
        main_panel = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True)

        # 左侧编辑区
        left_panel = ttk.Frame(main_panel)
        self._build_request_editor(left_panel)
        self._build_poc_editor(left_panel)
        main_panel.add(left_panel, weight=2)

        # 右侧控制台
        right_panel = ttk.PanedWindow(main_panel, orient=tk.VERTICAL)
        self._build_console(right_panel)
        self._build_batch_panel(right_panel)
        main_panel.add(right_panel, weight=1)

    def _build_request_editor(self, parent):
        """请求数据编辑区"""
        frame = ttk.LabelFrame(parent, text="📡 原始请求数据")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.raw_request = scrolledtext.ScrolledText(
            frame, 
            height=10,
            wrap=tk.WORD,
            font=('Consolas', 10),
            undo=True
        )
        self.raw_request.pack(fill=tk.BOTH, expand=True)
        ttk.Button(frame, text="解析请求生成POC", command=self._parse_request).pack(pady=5)

    def _build_poc_editor(self, parent):
        """POC代码编辑区"""
        frame = ttk.LabelFrame(parent, text="🛠 POC代码编辑")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.poc_editor = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Fira Code', 11),
            bg='#f7f7f7',
            undo=True
        )
        self.poc_editor.pack(fill=tk.BOTH, expand=True)

    def _build_console(self, parent):
        """验证结果控制台"""
        frame = ttk.LabelFrame(parent, text="🔍 验证结果")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.console = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            state='disabled',
            font=('等线', 10),
            background='#f0f0f0'
        )
        self.console.pack(fill=tk.BOTH, expand=True)

    def _build_batch_panel(self, parent):
        """批量操作面板"""
        frame = ttk.LabelFrame(parent, text="📁 批量任务")
        frame.pack(fill=tk.BOTH, padx=10, pady=5)

        # 操作按钮
        ttk.Button(frame, text="导入URL列表", command=self._import_urls).pack(pady=5)
        
        # URL列表
        self.url_listbox = tk.Listbox(
            frame,
            height=12,
            selectbackground='#cce5ff',
            activestyle='none'
        )
        self.url_listbox.pack(fill=tk.BOTH, expand=True)
        
        # 进度条
        self.progress = ttk.Progressbar(frame, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)

    def _create_toolbar(self):
        """工具栏"""
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X)
        
        actions = [
            ("💾 保存POC", self._save_poc),
            ("⚡ 单点验证", self._validate_single),
            ("🚀 批量验证", self._validate_batch),
            ("📊 生成报告", self._save_report)
        ]
        
        for text, cmd in actions:
            btn = ttk.Button(toolbar, text=text, command=cmd)
            btn.pack(side=tk.LEFT, padx=2)

    def _bind_events(self):
        """事件绑定"""
        self.url_listbox.bind("<Delete>", lambda e: self._delete_selected_url())

    # ----------------- 核心功能 -----------------
    def _parse_request(self):
        """解析HTTP请求生成POC模板"""
        raw_text = self.raw_request.get("1.0", tk.END).strip()
        if not raw_text:
            messagebox.showwarning("输入错误", "请输入原始请求数据")
            return

        try:
            # 解析请求方法
            first_line = raw_text.split('\n')
            method_match = re.match(r'^(GET|POST|PUT|DELETE)\s+([^\s]+)', first_line)
            if not method_match:
                raise ValueError("无法识别请求方法")
            method, path = method_match.groups()

            # 解析请求头
            headers = {}
            for line in raw_text.split('\n')[1:]:
                if ': ' in line and not line.strip().startswith(('{', '[')):
                    key, val = line.split(': ', 1)
                    headers[key.strip()] = val.strip()

            # 解析请求体
            body = None
            if '\n\n' in raw_text:
                body = raw_text.split('\n\n')[-1]

            # 生成POC模板
            template = f'''# Auto-Generated POC ({datetime.now().strftime('%Y-%m-%d')})
import requests

def verify(url):
    """漏洞验证函数"""
    target_url = f"{{url.rstrip('/')}}{path}"
    try:
        response = requests.request(
            method="{method}",
            url=target_url,
            headers={headers},
            data={repr(body) if body else None},
            timeout=5,
            verify=False
        )
        return _check_response(response)
    except Exception as e:
        print(f"验证失败: {{str(e)}}")
        return False

def _check_response(resp):
    """响应检测逻辑"""
    # 示例检测规则：状态码为200且包含特征字符串
    return (resp.status_code == 200 
            and 'vulnerable_flag' in resp.text)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python poc.py <url>")
        sys.exit(1)
    print(verify(sys.argv))
'''
            self.poc_editor.delete('1.0', tk.END)
            self.poc_editor.insert(tk.END, template)
            self._log("POC模板生成成功！")

        except Exception as e:
            messagebox.showerror("解析失败", f"请求格式错误: {str(e)}")

    def _validate_single(self):
        """单URL验证"""
        target = filedialog.askstring("目标输入", "请输入待检测URL:")
        if not target:
            return
        
        self._execute_poc(target)

    def _validate_batch(self):
        """批量验证"""
        if self.url_listbox.size() == 0:
            messagebox.showwarning("空列表", "请先导入URL列表")
            return
        
        self.progress['value'] = 0
        total = self.url_listbox.size()
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for i in range(total):
                url = self.url_listbox.get(i)
                futures.append(executor.submit(self._execute_poc, url))
            
            for i, future in enumerate(futures):
                try:
                    future.result(timeout=15)
                    self.progress['value'] = (i+1)/total*100
                    self.update()
                except TimeoutError:
                    self._log(f"验证超时: {url}")

    def _execute_poc(self, url):
        """执行POC验证"""
        with open('_temp_poc.py', 'w', encoding='utf-8') as f:
            f.write(self.poc_editor.get('1.0', tk.END))
        
        try:
            result = subprocess.run(
                ['python', '_temp_poc.py', url],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout.strip()
            if output.lower() == 'true':
                self._log(f"[✔] {url} 存在漏洞")
            else:
                self._log(f"[✘] {url} 未检测到漏洞")
        except subprocess.TimeoutExpired:
            self._log(f"[⌛] {url} 验证超时")

    def _import_urls(self):
        """导入URL列表"""
        filetypes = [('文本文件', '*.txt'), ('Excel', '*.xlsx')]
        if path := filedialog.askopenfilename(filetypes=filetypes):
            try:
                if path.endswith('.xlsx'):
                    df = pd.read_excel(path)
                    urls = df.iloc[:,0].dropna().tolist()
                else:
                    with open(path, 'r', encoding='utf-8') as f:
                        urls = [line.strip() for line in f if line.strip()]
                
                self.url_listbox.delete(0, tk.END)
                for url in urls[:1000]:
                    self.url_listbox.insert(tk.END, url)
                
                self._log(f"成功导入 {len(urls)} 个URL")
            except Exception as e:
                messagebox.showerror("导入失败", str(e))

    def _delete_selected_url(self):
        """删除选中URL"""
        for i in reversed(self.url_listbox.curselection()):
            self.url_listbox.delete(i)
        self._log("已删除选中URL")

    def _save_poc(self):
        """保存POC文件"""
        if path := filedialog.asksaveasfilename(
            defaultextension=".py",
            filetypes=[("Python文件", "*.py"), ("All Files", "*.*")]
        ):
            with open(path, 'w', encoding='utf-8') as f:
                content = f"# Auto-Saved POC\n{self.poc_editor.get('1.0', tk.END)}"
                f.write(content)
            self._log(f"POC已保存至: {path}")

    def _save_report(self):
        """保存验证报告"""
        content = self.console.get("1.0", tk.END)
        if not content.strip():
            messagebox.showwarning("空内容", "没有可保存的结果")
            return
        
        if path := filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("All Files", "*.*")]
        ):
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"安全检测报告\n{'='*30}\n")
                f.write(f"生成时间: {datetime.now()}\n\n")
                f.write(content)
            self._log(f"报告已保存至: {path}")

    def _log(self, message):
        """控制台日志"""
        self.console.config(state='normal')
        self.console.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.console.see(tk.END)
        self.console.config(state='disabled')

if __name__ == "__main__":
    app = POCGenerator()
    app.mainloop()
