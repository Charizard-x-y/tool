"""
大小写组合
作者：Charizard_xy
仅做学习使用，请勿用于非法用途
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import itertools
import re
import threading

class CaseCombinationGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("大小写组合")
        self.setup_ui()
        
        self.current_combinations = []
        self.current_progress = 0
        self.is_generating = False
        self.error_message = ""

    def setup_ui(self):
        # 输入部分
        input_frame = ttk.Frame(self.root)
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        ttk.Label(input_frame, text="输入字符串:").grid(row=0, column=0, sticky="w")
        self.input_var = tk.StringVar()
        self.input_entry = ttk.Entry(input_frame, textvariable=self.input_var, width=50)
        self.input_entry.grid(row=0, column=1, sticky="ew")
        self.input_entry.bind("<KeyRelease>", lambda e: self.generate_combinations())

        # 输出部分
        output_frame = ttk.Frame(self.root)
        output_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        
        ttk.Label(output_frame, text="输出结果:").grid(row=0, column=0, sticky="nw")
        
        self.output_text = tk.Text(output_frame, wrap=tk.NONE, width=60, height=15)
        vsb = ttk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        hsb = ttk.Scrollbar(output_frame, orient="horizontal", command=self.output_text.xview)
        self.output_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.output_text.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")

        # 进度条和统计
        stats_frame = ttk.Frame(self.root)
        stats_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        
        self.progress = ttk.Progressbar(stats_frame, mode="determinate")
        self.progress.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        self.stats_label = ttk.Label(stats_frame, text="生成数量: 0")
        self.stats_label.pack(side=tk.RIGHT, padx=5)

        # 导出按钮
        export_frame = ttk.Frame(self.root)
        export_frame.grid(row=3, column=0, padx=10, pady=10, sticky="e")
        self.export_button = ttk.Button(export_frame, text="导出为TXT", command=self.export_to_txt)
        self.export_button.pack()

        # 布局配置
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        output_frame.grid_rowconfigure(1, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)

    def generate_combinations(self):
        s = self.input_var.get().strip()
        if not s:
            self.reset_ui()
            return

        if self.is_generating:
            return

        letter_count = sum(1 for c in s if c.isalpha())
        total = 2 ** letter_count if letter_count > 0 else 1
        
        self.progress["maximum"] = total
        self.progress["value"] = 0
        self.stats_label.config(text=f"生成数量: 0 / {total}")
        
        self.input_entry.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        
        self.is_generating = True
        self.current_progress = 0
        self.error_message = ""
        
        threading.Thread(target=self.generate_in_thread, args=(s,), daemon=True).start()
        self.update_progress()

    def generate_in_thread(self, s):
        try:
            options = []
            letter_count = 0
            for c in s:
                if c.isalpha():
                    options.append([c.lower(), c.upper()])
                    letter_count += 1
                else:
                    options.append([c])

            total = 2 ** letter_count if letter_count > 0 else 1
            self.current_combinations = []
            
            for idx, comb in enumerate(itertools.product(*options), 1):
                self.current_combinations.append("".join(comb))
                self.current_progress = idx
        except Exception as e:
            self.error_message = str(e)
            self.current_progress = -1
        finally:
            self.is_generating = False

    def update_progress(self):
        if self.is_generating:
            if self.current_progress == -1:
                messagebox.showerror("错误", self.error_message)
                self.reset_ui()
            else:
                self.progress["value"] = self.current_progress
                self.stats_label.config(
                    text=f"生成数量: {self.current_progress} / {self.progress['maximum']}"
                )
                self.root.after(50, self.update_progress)
        else:
            self.progress["value"] = self.progress["maximum"]
            self.stats_label.config(text=f"生成数量: {self.progress['maximum']}")
            self.input_entry.config(state=tk.NORMAL)
            self.export_button.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "\n".join(self.current_combinations))

    def reset_ui(self):
        self.input_entry.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)
        self.progress["value"] = 0
        self.stats_label.config(text="生成数量: 0")
        self.current_combinations = []
        self.output_text.delete(1.0, tk.END)

    def export_to_txt(self):
        if not self.current_combinations:
            messagebox.showwarning("警告", "没有可导出的内容")
            return

        original_str = self.input_var.get().strip()
        cleaned_name = re.sub(r'[\\/*?:"<>|]', '_', original_str)[:50]
        if not cleaned_name:
            cleaned_name = "combination_results"

        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt")],
                initialfile=f"{cleaned_name}.txt"
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(self.current_combinations))
                messagebox.showinfo("成功", f"文件已保存到:\n{file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CaseCombinationGenerator(root)
    root.mainloop()

"""
大小写组合
作者：Charizard_xy
仅做学习使用，请勿用于非法用途
"""