"""
JS全能分析器 v1.0
核心依赖：pip install pyyaml
作者：Charizard_xy
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import json
import yaml
import xml.etree.ElementTree as ET

class POCGenerator:
    def __init__(self, master):
        self.master = master
        master.title("POC生成器 v2.0")
        master.geometry("800x600")
        
        # 样式配置
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('微软雅黑', 10))
        self.style.configure('TButton', font=('微软雅黑', 10))
        self.style.map('TButton', background=[('active', '#4a90e2'), ('!disabled', '#357abd')])

        # 主布局
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 请求输入区
        self.req_frame = ttk.LabelFrame(self.main_frame, text="请求配置")
        self.req_frame.pack(fill=tk.X, pady=5)
        
        self.req_text = scrolledtext.ScrolledText(self.req_frame, height=8, wrap=tk.WORD)
        self.req_text.pack(fill=tk.X, padx=5, pady=5)

        # 检测配置区
        self.detect_frame = ttk.LabelFrame(self.main_frame, text="检测配置")
        self.detect_frame.pack(fill=tk.X, pady=5)
        
        self.keyword_label = ttk.Label(self.detect_frame, text="关键字:")
        self.keyword_label.grid(row=0, column=0, padx=5, sticky=tk.W)
        self.keyword_entry = ttk.Entry(self.detect_frame, width=30)
        self.keyword_entry.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        self.desc_label = ttk.Label(self.detect_frame, text="漏洞描述:")
        self.desc_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.desc_entry = ttk.Entry(self.detect_frame, width=50)
        self.desc_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=tk.EW)

        # 格式选择
        self.format_frame = ttk.LabelFrame(self.main_frame, text="输出格式")
        self.format_frame.pack(fill=tk.X, pady=5)
        
        self.format_var = tk.StringVar(value="json")
        formats = [("JSON", "json"), ("XML", "xml"), ("YAML", "yaml")]
        for idx, (text, val) in enumerate(formats):
            rb = ttk.Radiobutton(self.format_frame, text=text, variable=self.format_var, value=val)
            rb.grid(row=0, column=idx, padx=10, pady=5, sticky=tk.W)

        # 操作按钮
        self.btn_frame = ttk.Frame(self.main_frame)
        self.btn_frame.pack(pady=10)
        self.send_btn = ttk.Button(self.btn_frame, text="发送请求并生成POC", command=self.generate_poc)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        
        # 结果展示
        self.result_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def generate_poc(self):
        try:
            # 获取请求数据
            req_data = self.req_text.get("1.0", tk.END).strip()
            keyword = self.keyword_entry.get().strip()
            description = self.desc_entry.get().strip()
            format_type = self.format_var.get()

            # 发送请求
            response = requests.request(
                method='POST',
                url='http://target.com/api',
                headers={'Content-Type': 'application/json'},
                data=req_data,
                timeout=10
            )
            
            # 检测关键字
            if keyword in response.text:
                status = "漏洞存在"
            else:
                status = "未检测到漏洞"

            # 生成POC模板
            poc_data = {
                "description": description,
                "request": req_data,
                "response": response.text,
                "status": status,
                "keyword": keyword
            }

            # 格式转换
            if format_type == "json":
                output = json.dumps(poc_data, indent=2)
            elif format_type == "xml":
                root = ET.Element("poc")
                for key, value in poc_data.items():
                    elem = ET.SubElement(root, key)
                    elem.text = str(value)
                output = ET.tostring(root, encoding='unicode')
            elif format_type == "yaml":
                output = yaml.dump(poc_data, allow_unicode=True)

            # 显示结果
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, output)
            
        except Exception as e:
            messagebox.showerror("错误", f"发生异常: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = POCGenerator(root)
    root.mainloop()
