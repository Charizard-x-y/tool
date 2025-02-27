"""
JS全能分析器 v1.0
核心功能：双模式解析 + 智能搜索 + 结构化导出
作者：Charizard_xy
"""
import re
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinterdnd2 import TkinterDnD, DND_FILES, DND_TEXT
from threading import Thread
from urllib.parse import urlparse
from datetime import datetime

class JSAnalyzerPro(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("JS全能分析器 v1.0")
        self.geometry("1300x850")
        self._init_ui()
        self._init_data()

    def _init_ui(self):
        """初始化界面组件"""
        self.style = ttk.Style()
        self.style.configure("Treeview.Heading", font=('微软雅黑', 10, 'bold'))
        self._create_input_panel()
        self._create_search_panel()
        self._create_main_view()
        self._create_status_bar()

    def _init_data(self):
        """初始化数据存储"""
        self.code_data = {}
        self.current_source = ""
        self.last_search = ""
        self.search_cache = {}

    # ------------------- UI组件构建 -------------------
    def _create_input_panel(self):
        """创建顶部输入面板"""
        input_frame = ttk.Frame(self)
        input_frame.pack(fill=tk.X, padx=10, pady=8)
        
        # 模式切换
        self.mode_var = tk.StringVar(value="url")
        ttk.Radiobutton(input_frame, text="URL模式", variable=self.mode_var,
                      value="url", command=self._toggle_mode).grid(row=0, column=0)
        ttk.Radiobutton(input_frame, text="文件模式", variable=self.mode_var,
                      value="file", command=self._toggle_mode).grid(row=0, column=1)
        
        # URL输入
        self.url_entry = ttk.Entry(input_frame, width=65, font=("Consolas", 11))
        self.url_entry.grid(row=0, column=2, padx=15)
        self.url_entry.drop_target_register(DND_TEXT)
        self.url_entry.dnd_bind("<<Drop>>", self._handle_drop)
        
        # 文件拖拽
        self.file_label = ttk.Label(input_frame, text="拖拽JS文件至此", 
                                 relief="groove", width=40)
        self.file_label.drop_target_register(DND_FILES)
        self.file_label.dnd_bind("<<Drop>>", self._handle_file_drop)
        
        # 操作按钮
        ttk.Button(input_frame, text="获取", command=self._fetch).grid(row=0, column=3)
        ttk.Button(input_frame, text="清除", command=self._clear).grid(row=0, column=4)

    def _create_search_panel(self):
        """创建搜索面板"""
        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=15, pady=8)
        
        # 搜索输入
        self.search_entry = ttk.Entry(search_frame, width=45, font=("微软雅黑", 11))
        self.search_entry.pack(side=tk.LEFT)
        self.search_entry.bind("<KeyRelease>", self._search)
        
        # 过滤条件
        self.filter_combo = ttk.Combobox(search_frame, 
                                      values=["全部", "函数", "变量", "事件"],
                                      state="readonly", width=8)
        self.filter_combo.set("全部")
        self.filter_combo.pack(side=tk.LEFT, padx=8)
        
        # 正则模式
        self.regex_btn = ttk.Checkbutton(search_frame, text="⚡ 正则", 
                                      style="Toggle.TButton")
        self.regex_btn.pack(side=tk.LEFT)
        
        # 高亮控制
        ttk.Button(search_frame, text="♻️ 重置", command=self._reset_highlight).pack(side=tk.RIGHT)

    def _create_main_view(self):
        """创建主视图区"""
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # 树形结构
        tree_frame = ttk.Frame(paned, width=350)
        self.tree = ttk.Treeview(tree_frame, columns=("meta"), show="tree")
        vsb = ttk.Scrollbar(tree_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        paned.add(tree_frame)
        
        # 代码预览
        preview_frame = ttk.Frame(paned, width=650)
        self.preview_text = tk.Text(preview_frame, wrap=tk.WORD, font=("Consolas", 11),
                                  bg="#fcfcfc", padx=15, pady=15)
        vsb_text = ttk.Scrollbar(preview_frame, command=self.preview_text.yview)
        self.preview_text.configure(yscrollcommand=vsb_text.set)
        self.preview_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb_text.pack(side=tk.RIGHT, fill=tk.Y)
        paned.add(preview_frame)
        
        # 事件绑定
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)
        self.tree.bind("<Double-1>", self._quick_export)

    def _create_status_bar(self):
        """创建状态栏"""
        status_bar = ttk.Frame(self)
        status_bar.pack(fill=tk.X, pady=5)
        self.status_label = ttk.Label(status_bar, text="就绪")
        self.status_label.pack(side=tk.LEFT)
        ttk.Button(status_bar, text="导出全部", command=self._export_all).pack(side=tk.RIGHT)
        ttk.Button(status_bar, text="导出选中", command=self._export_selected).pack(side=tk.RIGHT)

    # ------------------- 核心逻辑 -------------------
    def _toggle_mode(self):
        """切换输入模式"""
        if self.mode_var.get() == "url":
            self.file_label.grid_remove()
            self.url_entry.grid()
        else:
            self.url_entry.grid_remove()
            self.file_label.grid(row=0, column=2)

    def _handle_drop(self, event):
        """处理拖拽输入"""
        content = event.data
        if self.mode_var.get() == "url":
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, content.strip("{}"))

    def _handle_file_drop(self, event):
        """处理文件拖拽"""
        path = event.data.strip("{}")
        self._process_file(path)

    def _fetch(self):
        """获取内容"""
        if self.mode_var.get() == "url":
            url = self.url_entry.get().strip()
            if not self._validate_url(url):
                messagebox.showerror("错误", "无效URL")
                return
            Thread(target=self._process_url, args=(url,)).start()
        else:
            path = filedialog.askopenfilename(filetypes=[("JS Files", "*.js")])
            if path:
                self._process_file(path)

    def _validate_url(self, url):
        """验证URL有效性"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False

    def _process_url(self, url):
        """处理远程内容"""
        try:
            self._update_status(f"获取中: {url}")
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            
            if 'javascript' not in response.headers.get('Content-Type', ''):
                raise ValueError("非JS文件")
                
            self.code_data = self._parse(response.text)
            self.current_source = f"URL: {url} ({datetime.now():%Y-%m-%d %H:%M})"
            self.after(0, self._refresh_ui)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("错误", str(e)))
        finally:
            self._update_status("就绪")

    def _process_file(self, path):
        """处理本地文件"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.code_data = self._parse(content)
            self.current_source = f"文件: {path}"
            self._refresh_ui()
        except Exception as e:
            messagebox.showerror("错误", f"文件错误: {str(e)}")

    def _parse(self, code):
        """解析引擎"""
        patterns = {
            'Functions': r'(?<!//)\s*(function\s+\w+\s*$.*?$\s*{[\s\S]*?})\s*',
            'ArrowFunctions': r'(?:const|let)\s+\w+\s*=\s*$.*?$\s*=>\s*{[\s\S]*?}',
            'Class': r'class\s+\w+\s*{([\s\S]*?)}',
            'Variables': r'\b(var|let|const)\s+([^=;]+)[=;]',
            'Events': r'\.addEventListener$[\'"](.+?)[\'"]\s*,\s*(.+?)$'
        }
        return {k: re.findall(v, code) for k, v in patterns.items()}

    def _refresh_ui(self):
        """刷新界面"""
        self.tree.delete(*self.tree.get_children())
        for cat, items in self.code_data.items():
            parent = self.tree.insert("", tk.END, text=f"{cat} [{len(items)}]")
            for idx, item in enumerate(items, 1):
                self.tree.insert(parent, tk.END, text=f"#{idx}", values=(item,))

    def _search(self, event=None):
        """搜索"""
        query = self.search_entry.get().strip()
        category = self.filter_combo.get()
        use_regex = self.regex_btn.instate(['selected'])
        
        self.tree.delete(*self.tree.get_children())
        for cat, items in self.code_data.items():
            if category != "全部" and category not in cat:
                continue
                
            parent = self.tree.insert("", tk.END, text=cat)
            for item in items:
                if self._is_match(str(item), query, use_regex):
                    self.tree.insert(parent, tk.END, text=self._preview(item), values=(item,))
        
        self._highlight(query, use_regex)

    def _is_match(self, content, pattern, regex):
        """匹配逻辑"""
        if not pattern: return True
        try:
            return re.search(pattern, content, re.I) if regex else pattern.lower() in content.lower()
        except re.error:
            return False

    def _highlight(self, pattern, regex):
        """代码高亮"""
        self.preview_text.tag_remove("highlight", "1.0", tk.END)
        if not pattern: return
        
        content = self.preview_text.get("1.0", tk.END)
        flags = re.IGNORECASE if not regex else 0
        pattern = re.escape(pattern) if not regex else pattern
        
        for match in re.finditer(pattern, content, flags):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            self.preview_text.tag_add("highlight", start, end)
            
        self.preview_text.tag_config("highlight", background="#fff3cd")

    def _reset_highlight(self):
        """重置高亮"""
        self.search_entry.delete(0, tk.END)
        self.preview_text.tag_remove("highlight", "1.0", tk.END)

    # ------------------- 数据导出 -------------------
    def _export_all(self):
        """导出全部数据"""
        self._export(self.code_data)

    def _export_selected(self):
        """导出选中项"""
        selected = [self.tree.item(i)["values"] for i in self.tree.selection()]
        self._export({"Selected": selected})

    def _quick_export(self, event):
        """快速导出"""
        selected = self.tree.item(self.tree.focus())["values"]
        if selected:
            self._export({"Quick Export": [selected]})

    def _export(self, data):
        """通用导出方法"""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("JSON", "*.json")]
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"// 导出时间: {datetime.now():%Y-%m-%d %H:%M}\n")
                f.write(f"// 来源: {self.current_source}\n\n")
                for cat, items in data.items():
                    f.write(f"==== {cat} ====\n")
                    for item in items:
                        f.write(f"{item}\n\n")

    # ------------------- 辅助功能 -------------------
    def _update_status(self, msg):
        """更新状态栏"""
        self.status_label.config(text=msg)

    def _show_detail(self, event):
        """显示详情"""
        selected = self.tree.item(self.tree.focus())["values"]
        if selected:
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, selected)

    def _preview(self, item):
        """生成预览文本"""
        return str(item)[:50] + "..." if len(str(item)) > 50 else str(item)

    def _clear(self):
        """清除所有"""
        self.code_data = {}
        self.current_source = ""
        self.tree.delete(*self.tree.get_children())
        self.preview_text.delete(1.0, tk.END)
        self.url_entry.delete(0, tk.END)
        self._update_status("已重置")

if __name__ == "__main__":
    app = JSAnalyzerPro()
    app.mainloop()
