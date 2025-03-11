import tkinter as tk
from tkinter import ttk
import requests
import hashlib
import uuid
import json
import os
import sys

# ====================
# 百度翻译API配置
# ====================
APP_ID = "YOUR_APP_ID"        # 百度控制台获取
SECRET_KEY = "YOUR_SECRET_KEY" # 百度Secret Key
API_URL = "https://fanyi-api.baidu.com/api/trans/vip/translate"

# 抑制libpng警告
if sys.platform.startswith('win'):
    os.environ['PATH'] += ';C:\\Program Files\\ImageMagick-7.0.11-Q16-HDRI'
os.environ['GRD_DEBUG'] = '0'  # 禁用图形调试输出

# 设置Qt平台插件（如果使用Qt后端）
os.environ['QT_LOGGING_RULES'] = '*.debug=false;*.warning=false'

# ====================
# 支持语言列表
# ====================
LANGUAGES = {
    "自动检测": "auto",
    "中文": "zh",
    "英语": "en",
    "日语": "jp",
    "韩语": "kor",
    "法语": "fra",
    "西班牙语": "spa",
    "俄语": "ru",
    "德语": "de",
    "意大利语": "it",
    "荷兰语": "nl",
    "葡萄牙语": "pt",
    "阿拉伯语": "ara",
    "泰语": "th",
    "越南语": "vie"
}

class BaiduTranslator:
    """百度翻译服务封装类"""
    
    def __init__(self):
        self.session = requests.Session()
        
    def translate(self, text, target_lang, src_lang="auto"):
        """执行翻译请求"""
        try:
            salt = str(uuid.uuid1())
            sign_str = APP_ID + text + salt + SECRET_KEY
            sign = hashlib.md5(sign_str.encode()).hexdigest()
            
            params = {
                "q": text,
                "from": src_lang,
                "to": target_lang,
                "appid": APP_ID,
                "salt": salt,
                "sign": sign
            }
            
            response = self.session.get(API_URL, params=params, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if "error_code" in result:
                return f"错误 [{result['error_code']}]: {result['error_msg']}"
                
            return "\n".join([item["dst"] for item in result["trans_result"]])
            
        except Exception as e:
            return f"请求失败: {str(e)}"

class TranslationApp:
    """主应用程序GUI"""
    
    def __init__(self, root):
        self.root = root
        self.translator = BaiduTranslator()
        self.setup_ui()
        self.setup_bindings()
        
    def setup_ui(self):
        """初始化用户界面"""
        self.root.title("这是一个翻译器")
        self.root.geometry("1000x680")
        
        # 输入区域
        input_frame = ttk.Frame(self.root)
        input_frame.pack(pady=15, fill=tk.X)
        
        ttk.Label(input_frame, text="输入文本（自动检测语言）:", font=('微软雅黑', 12)).pack(anchor=tk.W)
        self.input_text = tk.Text(input_frame, height=10, font=('微软雅黑', 11), wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, padx=10, pady=5)
        
        # 目标语言选择
        lang_frame = ttk.Frame(self.root)
        lang_frame.pack(pady=10, fill=tk.X)
        
        # 目标语言1
        self.target1_frame = ttk.Frame(lang_frame)
        self.target1_frame.pack(side=tk.LEFT, expand=True, padx=20)
        ttk.Label(self.target1_frame, text="目标语言 1:").pack()
        self.lang1 = ttk.Combobox(
            self.target1_frame,
            values=list(LANGUAGES.keys())[1:],  # 排除auto
            state="readonly",
            font=('微软雅黑', 10)
        )
        self.lang1.current(0)
        self.lang1.pack()
        
        # 目标语言2
        self.target2_frame = ttk.Frame(lang_frame)
        self.target2_frame.pack(side=tk.RIGHT, expand=True, padx=20)
        ttk.Label(self.target2_frame, text="目标语言 2:").pack()
        self.lang2 = ttk.Combobox(
            self.target2_frame,
            values=list(LANGUAGES.keys())[1:],
            state="readonly",
            font=('微软雅黑', 10)
        )
        self.lang2.current(1)
        self.lang2.pack()
        
        # 翻译结果区域
        result_frame = ttk.Frame(self.root)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 结果框1
        self.trans_text1 = tk.Text(result_frame, height=15, wrap=tk.WORD)
        self.trans_text1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.copy_btn1 = ttk.Button(
            self.trans_text1, text="复制",
            command=lambda: self.copy_text(self.trans_text1)
        )
        self.copy_btn1.place(relx=0.98, rely=0.02, anchor=tk.NE)
        
        # 结果框2
        self.trans_text2 = tk.Text(result_frame, height=15, wrap=tk.WORD)
        self.trans_text2.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        self.copy_btn2 = ttk.Button(
            self.trans_text2, text="复制",
            command=lambda: self.copy_text(self.trans_text2)
        )
        self.copy_btn2.place(relx=0.98, rely=0.02, anchor=tk.NE)

    def setup_bindings(self):
        """设置事件绑定"""
        self.input_text.bind("<KeyRelease>", self.schedule_translation)
        self.lang1.bind("<<ComboboxSelected>>", self.schedule_translation)
        self.lang2.bind("<<ComboboxSelected>>", self.schedule_translation)
        
    def schedule_translation(self, event=None):
        """延迟翻译触发"""
        if hasattr(self, 'translation_job'):
            self.root.after_cancel(self.translation_job)
        self.translation_job = self.root.after(800, self.perform_translation)
        
    def perform_translation(self):
        """执行翻译操作"""
        input_text = self.input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.clear_results()
            return
            
        target1 = LANGUAGES[self.lang1.get()]
        target2 = LANGUAGES[self.lang2.get()]
        
        try:
            # 执行双翻译
            result1 = self.translator.translate(input_text, target1)
            result2 = self.translator.translate(input_text, target2)
            
            self.update_result(self.trans_text1, result1)
            self.update_result(self.trans_text2, result2)
            
        except Exception as e:
            error_msg = f"系统错误: {str(e)}"
            self.update_result(self.trans_text1, error_msg)
            self.update_result(self.trans_text2, error_msg)
            
    def update_result(self, widget, text):
        """更新结果文本框"""
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)
        
    def clear_results(self):
        """清空结果框"""
        self.update_result(self.trans_text1, "")
        self.update_result(self.trans_text2, "")
        
    def copy_text(self, text_widget):
        """复制文本到剪贴板"""
        text = text_widget.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

if __name__ == "__main__":
    root = tk.Tk()
    app = TranslationApp(root)
    root.mainloop()