"""
恶意文件名扫描
核心依赖：pip install requests ttkthemes
作者：Charizard_xy
仅做学习使用，请勿用于非法用途
"""
import os
import re
import json
import math
import hashlib
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
import subprocess
import platform
import requests

class AdvancedMalwareScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("随便扫一扫")
        self.root.geometry("1200x800")
        self.style = ttk.Style()
        self.style.configure('critical.Treeview', background='#ffcccc')
        self.style.configure('warning.Treeview', background='#fff3cd')
        
        # 初始化配置
        self.config = {
            'vt_api_key': '',
            'entropy_threshold': 7.2,
            'recent_days': 7,
            'signature_whitelist': ['Microsoft Corporation', 'Google LLC'],
            'max_file_size': 10000000  # 10MB
        }
        self.load_config()
        
        # 初始化扫描引擎
        self.scan_queue = queue.Queue()
        self.scanning = False
        self.total_files = 0
        self.processed_files = 0
        self.malware_db = []
        
        # 创建界面
        self.setup_ui()
        self.load_malware_db()

    def setup_ui(self):
        # 主框架
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 路径选择
        path_frame = ttk.Frame(self.main_frame)
        path_frame.pack(fill=tk.X, pady=5)
        ttk.Label(path_frame, text="扫描路径:").pack(side=tk.LEFT)
        self.path_entry = ttk.Entry(path_frame, width=50)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(path_frame, text="浏览", command=self.browse_path).pack(side=tk.LEFT)

        # 检测选项
        self.setup_detection_options()
        
        # 恶意文件库
        self.setup_malware_db_panel()
        
        # 扫描结果
        self.setup_result_tree()
        
        # 控制面板
        self.setup_control_panel()
        
        # 状态栏
        self.setup_status_bar()

    def setup_detection_options(self):
        options_frame = ttk.LabelFrame(self.main_frame, text="检测选项")
        options_frame.pack(fill=tk.X, pady=5)
        
        self.var_hash = tk.BooleanVar(value=True)
        self.var_sig = tk.BooleanVar(value=True)
        self.var_time = tk.BooleanVar(value=True)
        self.var_entropy = tk.BooleanVar(value=True)
        self.var_random = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="哈希验证", variable=self.var_hash).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(options_frame, text="数字签名", variable=self.var_sig).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(options_frame, text="创建时间", variable=self.var_time).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(options_frame, text="熵值分析", variable=self.var_entropy).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(options_frame, text="随机文件名", variable=self.var_random).pack(side=tk.LEFT, padx=5)
        ttk.Button(options_frame, text="配置", command=self.show_settings).pack(side=tk.RIGHT, padx=5)

    def setup_malware_db_panel(self):
        db_frame = ttk.LabelFrame(self.main_frame, text="恶意文件特征库")
        db_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.db_listbox = tk.Listbox(db_frame, height=8, selectmode=tk.SINGLE)
        self.db_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(db_frame)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        ttk.Button(btn_frame, text="添加", command=self.add_malware).pack(pady=2)
        ttk.Button(btn_frame, text="删除", command=self.remove_malware).pack(pady=2)
        ttk.Button(btn_frame, text="导入", command=self.import_db).pack(pady=2)
        ttk.Button(btn_frame, text="导出", command=self.export_db).pack(pady=2)

    def setup_result_tree(self):
        result_frame = ttk.LabelFrame(self.main_frame, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = [
            ('filename', '文件名', 150),
            ('path', '路径', 400),
            ('hash', '哈希值', 120),
            ('signature', '数字签名', 150),
            ('entropy', '熵值', 80),
            ('created', '创建时间', 120),
            ('random', '随机名', 80),
            ('status', '状态', 100)
        ]

        self.result_tree = ttk.Treeview(result_frame, columns=[col[0] for col in columns], show='headings')
        for col in columns:
            self.result_tree.heading(col[0], text=col[1])
            self.result_tree.column(col[0], width=col[2])
        self.result_tree.pack(fill=tk.BOTH, expand=True)
        self.result_tree.bind('<Double-1>', self.open_file_location)

    def setup_control_panel(self):
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        self.start_btn = ttk.Button(control_frame, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="停止", command=self.stop_scan).pack(side=tk.LEFT)

    def setup_status_bar(self):
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        self.progress = ttk.Progressbar(status_frame, mode='determinate')
        self.progress.pack(fill=tk.X, expand=True)
        self.status_label = ttk.Label(status_frame, text="准备就绪")
        self.status_label.pack(side=tk.LEFT)

    def load_config(self):
        try:
            with open('config.json') as f:
                self.config.update(json.load(f))
        except FileNotFoundError:
            pass

    def save_config(self):
        with open('config.json', 'w') as f:
            json.dump(self.config, f)

    def load_malware_db(self):
        try:
            with open('malware_db.json', 'r') as f:
                self.malware_db = json.load(f)
                self.update_db_list()
        except FileNotFoundError:
            self.malware_db = []

    # 核心扫描功能 --------------------------------------------------
    def start_scan(self):
        if not self.scanning:
            target_path = self.path_entry.get()
            if not os.path.isdir(target_path):
                messagebox.showerror("错误", "请输入有效路径！")
                return
            
            self.scanning = True
            self.start_btn.config(text="扫描中...")
            self.result_tree.delete(*self.result_tree.get_children())
            self.progress['value'] = 0
            self.status_label.config(text="正在准备扫描...")
            
            self.count_thread = threading.Thread(
                target=self.count_total_files,
                args=(target_path,),
                daemon=True
            )
            self.count_thread.start()

    def count_total_files(self, path):
        self.progress.config(mode='indeterminate')
        self.progress.start()
        total = 0
        for root, dirs, files in os.walk(path):
            if not self.scanning:
                break
            total += len(files)
        if self.scanning:
            self.total_files = total
            self.root.after(0, lambda: self.start_scan_thread(path))

    def start_scan_thread(self, path):
        self.progress.stop()
        self.progress.config(mode='determinate', maximum=self.total_files)
        self.status_label.config(text=f"总文件数: {self.total_files}")
        
        self.scan_thread = threading.Thread(
            target=self.scan_directory,
            args=(path,),
            daemon=True
        )
        self.scan_thread.start()
        self.monitor_scan_progress()

    def scan_directory(self, path):
        self.processed_files = 0
        for root, dirs, files in os.walk(path):
            if not self.scanning:
                break
            for filename in files:
                if not self.scanning:
                    break
                filepath = os.path.join(root, filename)
                file_info = self.analyze_file(filepath)
                if self.is_malicious(file_info):
                    self.scan_queue.put(('ADD', file_info))
                self.scan_queue.put(('PROGRESS', 1))
        self.scan_queue.put(('COMPLETE', None))

    def analyze_file(self, filepath):
        try:
            if os.path.getsize(filepath) > self.config['max_file_size']:
                return None

            filename = os.path.basename(filepath)
            return {
                'filename': filename,
                'path': filepath,
                'hash': self.get_file_hash(filepath),
                'signature': self.check_signature(filepath),
                'entropy': self.calculate_entropy(filepath),
                'created': self.check_creation_time(filepath),
                'random': self.is_random_name(filename),
                'status': 'safe'
            }
        except Exception as e:
            return None

    def is_malicious(self, file_info):
        if not file_info:
            return False
            
        criteria = [
            file_info['filename'] in self.malware_db,
            file_info['hash'].get('vt_malicious', 0) > 0,
            file_info['signature'] == 'Invalid',
            file_info['entropy'] > self.config['entropy_threshold'],
            file_info['created'] == 'Recent',
            file_info['random']
        ]
        return any(criteria)

    # 检测方法实现 --------------------------------------------------
    def get_file_hash(self, filepath):
        if not self.var_hash.get():
            return {}
        
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                vt_result = self.check_virustotal(file_hash)
                return {
                    'sha256': file_hash,
                    'vt_malicious': vt_result
                }
        except:
            return {}

    def check_virustotal(self, file_hash):
        if not self.config['vt_api_key']:
            return 0
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.config['vt_api_key']}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()['data']['attributes']['last_analysis_stats']['malicious']
            return 0
        except:
            return 0

    def check_signature(self, filepath):
        if not self.var_sig.get() or platform.system() != 'Windows':
            return 'N/A'
        
        try:
            cmd = f'powershell -Command "Get-AuthenticodeSignature -FilePath \'{filepath}\' | Select-Object StatusMessage"'
            result = subprocess.check_output(cmd, shell=True).decode()
            return 'Valid' if 'Valid' in result else 'Invalid'
        except:
            return 'Error'

    def calculate_entropy(self, filepath):
        if not self.var_entropy.get():
            return 0.0
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4096)
                if not data:
                    return 0.0
                entropy = 0.0
                for x in range(256):
                    p_x = data.count(x)/len(data)
                    if p_x > 0:
                        entropy += -p_x * math.log2(p_x)
                return round(entropy, 2)
        except:
            return 0.0

    def check_creation_time(self, filepath):
        if not self.var_time.get():
            return 'N/A'
        
        try:
            create_time = datetime.fromtimestamp(os.path.getctime(filepath))
            is_recent = (datetime.now() - create_time) < timedelta(days=self.config['recent_days'])
            return 'Recent' if is_recent else 'Normal'
        except:
            return 'Error'

    def is_random_name(self, filename):
        if not self.var_random.get():
            return False
        
        name = os.path.splitext(filename)[0]
        pattern = re.compile(r'''
            (?:[0-9a-f]{16,}|   # 16位以上hex
            \d{10,}|           # 10位以上数字
            [a-z]{10,}|         # 10位以上小写字母
            [A-Z]{10,}|         # 10位以上大写字母
            [^a-zA-Z0-9]{5,})  # 5位以上特殊字符
        ''', re.X)
        return bool(pattern.match(name))

    # 界面交互方法 --------------------------------------------------
    def monitor_scan_progress(self):
        try:
            while True:
                item = self.scan_queue.get_nowait()
                if item[0] == 'ADD':
                    self.display_result(item[1])
                elif item[0] == 'PROGRESS':
                    self.update_progress(item[1])
                elif item[0] == 'COMPLETE':
                    self.stop_scan()
                    break
        except queue.Empty:
            pass
        
        if self.scanning:
            self.root.after(100, self.monitor_scan_progress)

    def display_result(self, file_info):
        tags = []
        if file_info['filename'] in self.malware_db:
            tags.append('critical')
        elif sum([
            file_info['vt_malicious'] > 0,
            file_info['signature'] == 'Invalid',
            file_info['entropy'] > self.config['entropy_threshold'],
            file_info['random']
        ]) >= 2:
            tags.append('warning')
        
        values = (
            file_info['filename'],
            file_info['path'],
            f"{file_info['hash'].get('sha256', '')[:8]}... ({file_info['hash'].get('vt_malicious', 0)}/60)",
            file_info['signature'],
            f"{file_info['entropy']} {'⚠️' if file_info['entropy'] > self.config['entropy_threshold'] else ''}",
            file_info['created'],
            'Yes' if file_info['random'] else 'No',
            self.get_status_text(file_info)
        )
        
        self.result_tree.insert('', tk.END, values=values, tags=tags)

    def get_status_text(self, file_info):
        if file_info['filename'] in self.malware_db:
            return '已知恶意文件'
        if file_info['vt_malicious'] > 10:
            return '多引擎检测到恶意'
        if file_info['signature'] == 'Invalid':
            return '签名无效'
        if file_info['entropy'] > self.config['entropy_threshold']:
            return '高熵值文件'
        if file_info['random']:
            return '可疑随机名'
        return '安全'

    def update_progress(self, increment):
        self.processed_files += increment
        self.progress['value'] = self.processed_files
        percent = self.processed_files / self.total_files * 100
        self.status_label.config(
            text=f"扫描进度: {self.processed_files}/{self.total_files} ({percent:.1f}%)"
        )

    def stop_scan(self):
        self.scanning = False
        self.start_btn.config(text="开始扫描")
        self.status_label.config(text="扫描完成" if self.processed_files == self.total_files else "扫描已停止")
        self.progress.stop()

    # 文件库管理方法 -----------------------------------------------
    def add_malware(self):
        new_malware = tk.simpledialog.askstring("添加恶意文件", "输入文件名:")
        if new_malware and new_malware not in self.malware_db:
            self.malware_db.append(new_malware)
            self.update_db_list()

    def remove_malware(self):
        selection = self.db_listbox.curselection()
        if selection:
            index = selection[0]
            del self.malware_db[index]
            self.update_db_list()

    def import_db(self):
        filepath = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filepath:
            with open(filepath, 'r') as f:
                self.malware_db = json.load(f)
                self.update_db_list()

    def export_db(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".json")
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(self.malware_db, f)

    def update_db_list(self):
        self.db_listbox.delete(0, tk.END)
        for item in self.malware_db:
            self.db_listbox.insert(tk.END, item)

    # 配置管理 ----------------------------------------------------
    def show_settings(self):
        settings_win = tk.Toplevel(self.root)
        settings_win.title("高级设置")
        
        ttk.Label(settings_win, text="VirusTotal API Key:").grid(row=0, column=0)
        api_entry = ttk.Entry(settings_win, width=40)
        api_entry.insert(0, self.config['vt_api_key'])
        api_entry.grid(row=0, column=1)
        
        ttk.Label(settings_win, text="熵值阈值:").grid(row=1, column=0)
        entropy_spin = ttk.Spinbox(settings_win, from_=4.0, to=8.0, increment=0.1)
        entropy_spin.set(self.config['entropy_threshold'])
        entropy_spin.grid(row=1, column=1)
        
        ttk.Label(settings_win, text="最近文件天数:").grid(row=2, column=0)
        days_spin = ttk.Spinbox(settings_win, from_=1, to=30)
        days_spin.set(self.config['recent_days'])
        days_spin.grid(row=2, column=1)
        
        ttk.Button(settings_win, text="保存", command=lambda: self.save_settings(
            api_entry.get(),
            float(entropy_spin.get()),
            int(days_spin.get())
        ).grid(row=3, columnspan=2, pady=10))

    def save_settings(self, api_key, entropy, days):
        self.config.update({
            'vt_api_key': api_key,
            'entropy_threshold': entropy,
            'recent_days': days
        })
        self.save_config()
        messagebox.showinfo("成功", "配置已保存")

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def open_file_location(self, event):
        item = self.result_tree.selection()[0]
        filepath = self.result_tree.item(item, 'values')[1]
        if os.name == 'nt':
            os.startfile(os.path.dirname(filepath))
        else:
            os.system(f'open "{os.path.dirname(filepath)}"')

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedMalwareScanner(root)
    root.mainloop()

"""
恶意文件名扫描
核心依赖：pip install requests ttkthemes
作者：Charizard_xy
仅做学习使用，请勿用于非法用途
"""