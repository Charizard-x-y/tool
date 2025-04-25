"""
汉字转字母
核心依赖：pip install ttkbootstrap pypinyin pyperclip
作者：Charizard_xy
仅做学习使用，请勿用于非法用途
"""
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from pypinyin import lazy_pinyin
import itertools
import pyperclip

class PinyinConverter:
    def __init__(self, master):
        self.master = master
        master.title("汉字转字母")
        style = ttk.Style(theme='morph')

        # 输入区域
        input_frame = ttk.Frame(master)
        input_frame.pack(pady=10, fill=tk.X)
        ttk.Label(input_frame, text="输入汉字：", font=('微软雅黑', 10)).pack(side=tk.LEFT, padx=5)
        self.input_entry = ttk.Entry(input_frame, width=40)
        self.input_entry.pack(side=tk.LEFT, padx=5)
        self.input_entry.bind("<KeyRelease>", self.convert)

        # 全拼结果显示区域
        full_frame = ttk.LabelFrame(master, text="全拼组合", padding=10)
        full_frame.pack(pady=5, fill=tk.X, padx=10)
        
        self.full_combinations = {
            '全小写': ttk.Entry(full_frame, width=35),
            '全大写': ttk.Entry(full_frame, width=35),
            '首字母大写': ttk.Entry(full_frame, width=35),
            '驼峰式': ttk.Entry(full_frame, width=35)
        }
        
        for i, (name, entry) in enumerate(self.full_combinations.items()):
            ttk.Label(full_frame, text=name+":", width=10).grid(row=i, column=0, sticky='e')
            entry.grid(row=i, column=1, padx=5, pady=2)
            ttk.Button(full_frame, text="复制", 
                      command=lambda e=entry: self.copy_to_clipboard(e.get()),
                      width=6).grid(row=i, column=2, padx=5)

        # 首字母结果显示区域
        initial_frame = ttk.LabelFrame(master, text="首字母组合", padding=10)
        initial_frame.pack(pady=5, fill=tk.BOTH, expand=True, padx=10)
        
        self.initial_text = ScrolledText(initial_frame, width=40, height=6, font=('Consolas', 10))
        self.initial_text.pack(fill=tk.BOTH, expand=True)
        
        btn_frame = ttk.Frame(initial_frame)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="复制全部首字母", 
                  command=self.copy_all_initials, 
                  bootstyle=INFO).pack(side=tk.LEFT, padx=5)

        # 全局操作按钮
        control_frame = ttk.Frame(master)
        control_frame.pack(pady=10)
        ttk.Button(control_frame, text="一键复制全部内容", 
                  command=self.copy_all, 
                  bootstyle=SUCCESS).pack(padx=5)

    def convert(self, event=None):
        hanzi = self.input_entry.get()
        
        # 清空旧数据
        for entry in self.full_combinations.values():
            entry.delete(0, tk.END)
        self.initial_text.delete(1.0, tk.END)

        if not hanzi:
            return

        # 转换拼音
        pinyin_list = lazy_pinyin(hanzi)
        initials = [p[0] for p in pinyin_list if p]

        # 生成全拼组合
        full_str = ''.join(pinyin_list)
        self.full_combinations['全小写'].insert(0, full_str)
        self.full_combinations['全大写'].insert(0, full_str.upper())
        self.full_combinations['首字母大写'].insert(0, full_str.capitalize())
        self.full_combinations['驼峰式'].insert(0, ''.join([p.capitalize() for p in pinyin_list]))

        # 生成首字母组合
        if initials:
            combinations = [''.join(c) for c in itertools.product(
                *[(ch.lower(), ch.upper()) for ch in ''.join(initials)]
            )]
            self.initial_text.insert(tk.END, '\n'.join(sorted(set(combinations), key=lambda x: x.lower())))  # 去重并排序

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)

    def copy_all_initials(self):
        pyperclip.copy(self.initial_text.get(1.0, tk.END).strip())

    def copy_all(self):
        full = '\n'.join([entry.get() for entry in self.full_combinations.values()])
        initials = self.initial_text.get(1.0, tk.END).strip()
        pyperclip.copy(f"{full}\n{initials}")

if __name__ == '__main__':
    root = ttk.Window(themename='morph')
    root.geometry("500x600")
    app = PinyinConverter(root)
    root.mainloop()

"""
汉字转字母
核心依赖：pip install ttkbootstrap pypinyin pyperclip
作者：Charizard_xy
仅做学习使用，请勿用于非法用途
"""