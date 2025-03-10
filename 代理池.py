"""
代理池管理
作者：Charizard_xy
功能：爬取ip
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from bs4 import BeautifulSoup
import threading
import time
import random
import json
import os
from queue import Queue
from requests.adapters import HTTPAdapter

class ProxyPoolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IP代理池工具 v1.0 作者：charizard_xy")
        self.geometry("1200x800")
        
        # 初始化配置
        self.proxies = []
        self.current_proxy = None
        self.proxy_index = 0
        self.update_interval = 300
        self.is_running = False
        self.retry_config = {
            'max_retries': 5,
            'backoff_factor': 1.5,
            'status_forcelist': [500, 502, 503, 504, 408, 429],
            'timeout': 25
        }
        self.validation_params = {
            'url': 'http://httpbin.org/ip',
            'timeout': 10
        }
        self.sources = self.load_source_config()
        
        # 初始化界面
        self.create_widgets()
        self.create_menu()
        
        # 启动任务
        self.after(1000, self.periodic_tasks)
        self.update_proxy_pool()

    # ------------------ 核心功能 ------------------
    def update_proxy_pool(self):
        if not self.check_network_connection():
            return
        self.log("开始更新代理池...")
        threading.Thread(target=self.fetch_proxies, daemon=True).start()

    def fetch_proxies(self):
        proxy_queue = Queue()
        threads = []
        
        for source in self.sources:
            if source['enable']:
                t = threading.Thread(
                    target=getattr(self, source['parser_func']),
                    args=(proxy_queue, source),
                    daemon=True
                )
                t.start()
                threads.append(t)
                time.sleep(random.uniform(0.5, 1.5))
        
        for t in threads:
            t.join()
        
        self.process_proxy_queue(proxy_queue)

    def process_proxy_queue(self, queue):
        new_proxies = []
        while not queue.empty():
            new_proxies.append(queue.get())
        
        seen = set()
        self.proxies = [
            p for p in new_proxies
            if (p['ip'], p['port']) not in seen and not seen.add((p['ip'], p['port']))
        ]
        self.validate_proxies()

    def validate_proxies(self):
        valid_proxies = []
        threads = []
        
        def validate(proxy):
            try:
                protocol = 'https' if 'https' in proxy['type'] else 'http'
                proxies = {
                    'http': f"{protocol}://{proxy['ip']}:{proxy['port']}",
                    'https': f"{protocol}://{proxy['ip']}:{proxy['port']}"
                }
                start = time.time()
                r = requests.get(
                    self.validation_params['url'],
                    proxies=proxies,
                    timeout=self.validation_params['timeout']
                )
                if r.status_code == 200:
                    proxy['speed'] = f"{int((time.time()-start)*1000)}ms"
                    valid_proxies.append(proxy)
            except: pass

        for proxy in self.proxies:
            t = threading.Thread(target=validate, args=(proxy,), daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        self.proxies = valid_proxies
        self.update_proxy_list()
        self.log(f"验证完成，有效代理数：{len(self.proxies)}")

    # ------------------ 界面组件 ------------------
    def create_widgets(self):
        # 主面板
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 控制面板
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.btn_toggle = ttk.Button(control_frame, text="启动代理", command=self.toggle_proxy)
        self.btn_toggle.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(control_frame, text="切换间隔(秒):").pack(side=tk.LEFT)
        self.interval_entry = ttk.Entry(control_frame, width=8)
        self.interval_entry.insert(0, "300")
        self.interval_entry.pack(side=tk.LEFT)
        ttk.Button(control_frame, text="设置", command=self.set_interval).pack(side=tk.LEFT)
        
        ttk.Button(control_frame, text="手动更新", command=self.update_proxy_pool).pack(side=tk.LEFT)
        
        # 代理列表
        self.tree = ttk.Treeview(main_frame, columns=('ip', 'port', 'type', 'speed'), show='headings')
        self.tree.heading('ip', text='IP地址')
        self.tree.heading('port', text='端口')
        self.tree.heading('type', text='类型')
        self.tree.heading('speed', text='响应速度')
        self.tree.column('ip', width=200)
        self.tree.column('port', width=80)
        self.tree.column('type', width=100)
        self.tree.column('speed', width=100)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # 日志框
        self.log_area = scrolledtext.ScrolledText(main_frame, height=10)
        self.log_area.pack(fill=tk.BOTH)

    def create_menu(self):
        menubar = tk.Menu(self)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="导入配置", command=self.import_config)
        file_menu.add_command(label="导出配置", command=self.export_config)
        menubar.add_cascade(label="文件", menu=file_menu)
        
        # 配置菜单
        config_menu = tk.Menu(menubar, tearoff=0)
        config_menu.add_command(label="代理源管理", command=self.show_source_manager)
        config_menu.add_command(label="验证设置", command=self.show_validation_settings)
        menubar.add_cascade(label="配置", menu=config_menu)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        
        self.config(menu=menubar)

    # ------------------ 配置管理 ------------------
    def load_source_config(self, filename="sources.json"):
        default_config = [
            {
                "name": "西刺代理",
                "url": "https://www.xicidaili.com/nn/",
                "enable": True,
                "parser_func": "fetch_xici_proxies",
                "last_update": None,
                "status": "未检测",
                "stats": {"total": 0, "success": 0, "avg": 0, "last_count": 0}
            },
            {
                "name": "快代理",
                "url": "https://www.kuaidaili.com/free/intr/",
                "enable": True,
                "parser_func": "fetch_kuaidaili_proxies",
                "last_update": None,
                "status": "未检测",
                "stats": {"total": 0, "success": 0, "avg": 0, "last_count": 0}
            }
        ]
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    return json.load(f)
            return default_config
        except Exception as e:
            self.log(f"配置加载失败: {str(e)}")
            return default_config

    def save_source_config(self, filename="sources.json"):
        try:
            with open(filename, 'w') as f:
                json.dump(self.sources, f, indent=2)
            return True
        except Exception as e:
            self.log(f"配置保存失败: {str(e)}")
            return False

    def import_config(self):
        filepath = filedialog.askopenfilename(
            title="选择配置文件",
            filetypes=[("JSON files", "*.json")]
        )
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    self.sources = json.load(f)
                self.save_source_config()
                messagebox.showinfo("成功", "配置导入成功")
                self.update_proxy_pool()
            except Exception as e:
                messagebox.showerror("导入失败", f"错误信息：{str(e)}")

    def export_config(self):
        filepath = filedialog.asksaveasfilename(
            title="保存配置文件",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if filepath:
            if self.save_source_config(filepath):
                messagebox.showinfo("成功", "配置导出成功")
            else:
                messagebox.showerror("失败", "配置导出失败")

    # ------------------ 网络功能 ------------------
    def create_retry_session(self):
        session = requests.Session()
        adapter = HTTPAdapter(
            max_retries=self.retry_config['max_retries'],
            backoff_factor=self.retry_config['backoff_factor']
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def fetch_proxy_source(self, url, source):
        try:
            session = self.create_retry_session()
            response = session.get(
                url,
                headers={'User-Agent': self.get_random_user_agent()},
                timeout=self.retry_config['timeout']
            )
            response.raise_for_status()
            return response.text
        except Exception as e:
            self.log(f"[{source['name']}] 请求失败: {type(e).__name__}")
            return None

    # ------------------ 工具方法 ------------------
    def log(self, message):
        self.log_area.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        self.log_area.see(tk.END)

    def get_random_user_agent(self):
        return random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15'
        ])

    def check_network_connection(self):
        try:
            requests.get('https://www.baidu.com', timeout=10)
            return True
        except:
            messagebox.showerror("网络错误", "无法连接互联网")
            return False

    # ------------------ 事件处理 ------------------
    def toggle_proxy(self):
        self.is_running = not self.is_running
        self.btn_toggle.config(text="停止代理" if self.is_running else "启动代理")
        if self.is_running:
            self.start_proxy_rotation()

    def start_proxy_rotation(self):
        if self.proxies:
            self.current_proxy = self.proxies[self.proxy_index % len(self.proxies)]
            self.proxy_index += 1
            self.log(f"切换到代理：{self.current_proxy}")
        if self.is_running:
            self.after(self.update_interval * 1000, self.start_proxy_rotation)

    def set_interval(self):
        try:
            self.update_interval = max(30, int(self.interval_entry.get()))
            self.log(f"切换间隔设置为 {self.update_interval} 秒")
        except:
            messagebox.showerror("错误", "请输入有效数字")

    def update_proxy_list(self):
        self.tree.delete(*self.tree.get_children())
        for proxy in self.proxies:
            self.tree.insert('', 'end', values=(
                proxy['ip'],
                proxy['port'],
                proxy['type'],
                proxy.get('speed', '未知')
            ))

    def periodic_tasks(self):
        self.update_status_display()
        self.after(5000, self.periodic_tasks)

    def update_status_display(self):
        status = f"有效代理: {len(self.proxies)} | 最近更新: {time.strftime('%Y-%m-%d %H:%M')}"
        if hasattr(self, 'status_var'):
            self.status_var.set(status)

    # ------------------ 代理源抓取方法 ------------------
    def fetch_xici_proxies(self, queue, source):
        try:
            html = self.fetch_proxy_source(source['url'], source)
            if not html:
                source['status'] = "请求失败"
                return
                
            soup = BeautifulSoup(html, 'html.parser')
            table = soup.find('table', {'id': 'ip_list'})
            if not table:
                source['status'] = "解析失败"
                return
                
            count = 0
            for row in table.find_all('tr')[1:]:
                cells = row.find_all('td')
                if len(cells) > 5:
                    data = {
                        'ip': cells[1].text.strip(),
                        'port': cells[2].text.strip(),
                        'type': cells[5].text.lower()
                    }
                    queue.put(data)
                    count += 1
            
            source['status'] = f"成功获取 {count} 个"
            source['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.update_source_stats(source, count)

        except Exception as e:
            self.log(f"西刺代理抓取失败: {str(e)}")
            source['status'] = "抓取异常"

    def fetch_kuaidaili_proxies(self, queue, source):
        try:
            html = self.fetch_proxy_source(source['url'], source)
            if not html:
                source['status'] = "请求失败"
                return
                
            soup = BeautifulSoup(html, 'html.parser')
            table = soup.find('table')
            if not table:
                source['status'] = "解析失败"
                return
                
            count = 0
            for row in table.find_all('tr')[1:]:
                cells = row.find_all('td')
                if len(cells) > 6:
                    data = {
                        'ip': cells[0].text.strip(),
                        'port': cells[1].text.strip(),
                        'type': cells[3].text.lower()
                    }
                    queue.put(data)
                    count += 1
            
            source['status'] = f"成功获取 {count} 个"
            source['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.update_source_stats(source, count)

        except Exception as e:
            self.log(f"快代理抓取失败: {str(e)}")
            source['status'] = "抓取异常"

    def update_source_stats(self, source, count):
        stats = source.setdefault('stats', {'total': 0, 'success': 0, 'avg': 0, 'last_count': 0})
        stats['total'] += 1
        if count > 0:
            stats['success'] += 1
            stats['last_count'] = count
            stats['avg'] = (stats['avg'] * (stats['success']-1) + count) / stats['success']

    # ------------------ 对话框 ------------------
    def show_source_manager(self):
        SourceManager(self)

    def show_validation_settings(self):
        ValidationSettings(self)

    def show_about(self):
        messagebox.showinfo("关于", "IP代理池工具\n版本：6.0\n作者：Charaizard_xy")

class SourceManager(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("代理源管理")
        self.geometry("800x600")
        self.create_widgets()
        self.load_data()

    def create_widgets(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X)
        
        ttk.Button(toolbar, text="添加", command=self.add_source).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="刷新", command=self.load_data).pack(side=tk.LEFT)
        
        columns = ('name', 'status', 'last_update', 'success_rate')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        self.tree.heading('name', text='名称')
        self.tree.heading('status', text='状态')
        self.tree.heading('last_update', text='最后更新')
        self.tree.heading('success_rate', text='成功率')
        self.tree.pack(fill=tk.BOTH, expand=True)

    def load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for source in self.parent.sources:
            stats = source.get('stats', {})
            total = stats.get('total', 0)
            success = stats.get('success', 0)
            success_rate = f"{success/total*100:.1f}%" if total > 0 else "N/A"
            self.tree.insert('', 'end', values=(
                source['name'],
                source['status'],
                source.get('last_update', '从未更新'),
                success_rate
            ))

    def add_source(self):
        AddSourceDialog(self.parent)

class AddSourceDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("添加代理源")
        self.geometry("400x300")
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="名称:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.E)
        self.name_entry = ttk.Entry(self)
        self.name_entry.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(self, text="URL:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.E)
        self.url_entry = ttk.Entry(self)
        self.url_entry.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(self, text="解析函数:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.E)
        self.parser_combo = ttk.Combobox(self, values=[
            "fetch_xici_proxies", 
            "fetch_kuaidaili_proxies",
            "fetch_zdaye_proxies"
        ])
        self.parser_combo.grid(row=2, column=1, sticky=tk.W)
        
        ttk.Label(self, text="启用:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.E)
        self.enable_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, variable=self.enable_var).grid(row=3, column=1, sticky=tk.W)
        
        ttk.Button(self, text="保存", command=self.save).grid(row=4, columnspan=2, pady=10)

    def save(self):
        name = self.name_entry.get().strip()
        url = self.url_entry.get().strip()
        parser_func = self.parser_combo.get().strip()
        enable = self.enable_var.get()

        if not name:
            messagebox.showerror("错误", "请输入代理源名称")
            return
        if not url.startswith(('http://', 'https://')):
            messagebox.showerror("错误", "URL必须以http://或https://开头")
            return
        if not hasattr(self.parent, parser_func):
            messagebox.showerror("错误", "无效的解析函数")
            return

        new_source = {
            "name": name,
            "url": url,
            "parser_func": parser_func,
            "enable": enable,
            "status": "未检测",
            "last_update": None,
            "stats": {"total": 0, "success": 0, "avg": 0, "last_count": 0}
        }

        self.parent.sources.append(new_source)
        if self.parent.save_source_config():
            messagebox.showinfo("成功", "代理源添加成功")
            self.destroy()
            if hasattr(self.parent, 'source_manager'):
                self.parent.source_manager.load_data()
        else:
            messagebox.showerror("错误", "保存配置失败")

class ValidationSettings(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("验证设置")
        self.geometry("300x200")
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="验证URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.url_entry = ttk.Entry(self)
        self.url_entry.insert(0, self.parent.validation_params['url'])
        self.url_entry.grid(row=0, column=1)

        ttk.Label(self, text="超时时间(秒):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.timeout_entry = ttk.Entry(self)
        self.timeout_entry.insert(0, str(self.parent.validation_params['timeout']))
        self.timeout_entry.grid(row=1, column=1)

        ttk.Button(self, text="保存", command=self.save).grid(row=2, columnspan=2, pady=10)

    def save(self):
        try:
            self.parent.validation_params['url'] = self.url_entry.get()
            self.parent.validation_params['timeout'] = int(self.timeout_entry.get())
            messagebox.showinfo("成功", "验证参数已更新")
            self.destroy()
        except ValueError:
            messagebox.showerror("错误", "超时时间必须为整数")

if __name__ == "__main__":
    app = ProxyPoolApp()
    app.mainloop()
