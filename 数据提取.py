"""
数据提取工具
作者：Charizard_xy
功能：数据提取
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import os
import re

class AdvancedDataExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("数据提取")
        self.root.geometry("1000x700")
        self.root.resizable(False, False)
        self.data = {}
        self.current_df = pd.DataFrame()
        self.setup_ui()

    def setup_ui(self):
        style = ttk.Style()
        style.configure('TButton', padding=6)
        style.configure('TLabel', padding=6)
        style.configure('Treeview', rowheight=25)

        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 文件导入区域
        file_frame = ttk.LabelFrame(main_frame, text="文件导入", padding=10)
        file_frame.grid(row=0, column=0, sticky='ew', pady=5)
        
        ttk.Button(file_frame, text="选择文件", command=self.load_file).pack(side=tk.LEFT)
        ttk.Button(file_frame, text="批量导入", command=self.load_directory).pack(side=tk.LEFT, padx=5)

        # 高级搜索设置
        advanced_frame = ttk.LabelFrame(main_frame, text="高级提取设置", padding=10)
        advanced_frame.grid(row=1, column=0, sticky='ew', pady=5)

        ttk.Label(advanced_frame, text="前导字符数:").pack(side=tk.LEFT)
        self.before_chars = ttk.Entry(advanced_frame, width=8)
        self.before_chars.pack(side=tk.LEFT, padx=5)
        self.before_chars.insert(0, "50")

        ttk.Label(advanced_frame, text="后置字符数:").pack(side=tk.LEFT, padx=(10,0))
        self.after_chars = ttk.Entry(advanced_frame, width=8)
        self.after_chars.pack(side=tk.LEFT)
        self.after_chars.insert(0, "50")

        ttk.Label(advanced_frame, text="终止字符:").pack(side=tk.LEFT, padx=(10,0))
        self.stop_chars = ttk.Entry(advanced_frame, width=15)
        self.stop_chars.pack(side=tk.LEFT)
        self.stop_chars.insert(0, "。.;,，！!?？")

        ttk.Checkbutton(advanced_frame, text="包含关键字", variable=tk.BooleanVar(value=True)).pack(side=tk.LEFT, padx=10)

        # 控制区域
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, sticky='ew', pady=5)

        ttk.Label(control_frame, text="关键字搜索:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(control_frame, width=20)
        self.search_entry.pack(side=tk.LEFT)
        ttk.Button(control_frame, text="开始提取", command=self.advanced_search).pack(side=tk.LEFT, padx=5)

        # 结果显示区域
        result_frame = ttk.LabelFrame(main_frame, text="提取结果", padding=10)
        result_frame.grid(row=3, column=0, sticky='nsew', pady=5)

        self.tree = ttk.Treeview(result_frame, show='headings', selectmode='extended', columns=('提取内容'))
        self.tree.heading('提取内容', text='提取内容')
        self.tree.column('提取内容', width=800, anchor='w')
        
        vsb = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')

        # 操作按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, sticky='e', pady=5)
        ttk.Button(btn_frame, text="复制提取内容", command=self.copy_extracted).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="清空所有数据", command=self.clear_data).pack(side=tk.LEFT, padx=5)

        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        result_frame.rowconfigure(0, weight=1)
        result_frame.columnconfigure(0, weight=1)

    def load_file(self):
        filetypes = [('支持的文件', '*.csv *.xlsx *.txt')]
        filepath = filedialog.askopenfilename(filetypes=filetypes)
        if filepath:
            self.process_file(filepath)

    def load_directory(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            for fname in os.listdir(dir_path):
                if fname.split('.')[-1] in ['csv', 'xlsx', 'txt']:
                    self.process_file(os.path.join(dir_path, fname))

    def process_file(self, filepath):
        try:
            ext = filepath.split('.')[-1]
            if ext == 'csv':
                df = pd.read_csv(filepath)
            elif ext == 'xlsx':
                df = pd.read_excel(filepath)
            elif ext == 'txt':
                df = pd.read_csv(filepath, sep='\t', engine='python')
            else:
                return
            
            self.data[os.path.basename(filepath)] = df
            self.current_df = pd.concat(self.data.values(), ignore_index=True)
        except Exception as e:
            messagebox.showerror("错误", f"文件读取失败: {str(e)}")

    def extract_context(self, text, keyword):
        try:
            before = int(self.before_chars.get())
            after = int(self.after_chars.get())
        except:
            before = after = 50
        
        stop_chars = self.stop_chars.get()
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        matches = []
        
        for match in pattern.finditer(str(text)):
            # 向前扩展
            start = max(0, match.start() - before)
            prev_text = text[start:match.start()]
            for i, c in enumerate(reversed(prev_text)):
                if c in stop_chars:
                    start = match.start() - i
                    break

            # 向后扩展
            end = match.end() + after
            next_text = text[match.end():end]
            for i, c in enumerate(next_text):
                if c in stop_chars:
                    end = match.end() + i + 1
                    break

            extracted = text[start:end].strip()
            matches.append(extracted)
        
        return matches

    def advanced_search(self):
        keyword = self.search_entry.get()
        if not keyword:
            return
        
        self.tree.delete(*self.tree.get_children())
        results = []
        
        for _, row in self.current_df.iterrows():
            for _, value in row.items():
                matches = self.extract_context(str(value), keyword)
                if matches:
                    results.extend(matches)
        
        if results:
            for result in results:
                self.tree.insert('', 'end', values=(result,))
        else:
            messagebox.showinfo("提示", "未找到匹配内容")

    def copy_extracted(self):
        items = [self.tree.item(i)['values'][0] for i in self.tree.get_children()]
        if items:
            text_data = '\n'.join(items)
            self.root.clipboard_clear()
            self.root.clipboard_append(text_data)
            messagebox.showinfo("复制成功", f"已复制{len(items)}条提取内容")

    def clear_data(self):
        self.data.clear()
        self.current_df = pd.DataFrame()
        self.tree.delete(*self.tree.get_children())
        self.search_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedDataExtractorApp(root)
    root.mainloop()

"""
数据提取工具
作者：Charizard_xy
功能：数据提取
"""