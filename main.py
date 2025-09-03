import io
import tkinter as tk
from tkinter import ttk, messagebox
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
import time

import requests
from PIL import Image, ImageTk

import video
from bilibli import run_bili


class BiliFakePlayApp:
    def __init__(self, master):
        self.master = master
        self.master.title("B站刷视频")
        self.master.geometry("600x580")
        self.master.configure(bg="#f4f6fa")

        # ================== 输入区域 ==================
        input_frame = tk.Frame(master, bg="#ffffff", relief="groove", bd=1)
        input_frame.pack(pady=12, padx=20, fill="x")

        tk.Label(input_frame, text="请输入视频信息", bg="#ffffff",
                 font=("Microsoft YaHei", 12, "bold"),
                 fg="#333").pack(anchor="w", padx=10, pady=(5, 10))

        # 视频网址
        row1 = tk.Frame(input_frame, bg="#ffffff")
        row1.pack(fill="x", pady=5, padx=10)
        tk.Label(row1, text="视频网址：", bg="#ffffff", font=("Microsoft YaHei", 11)).pack(side="left")
        self.url_entry = tk.Entry(row1, width=40, font=("Microsoft YaHei", 10),
                                  relief="flat", bg="#f8f9fa",
                                  highlightthickness=1, highlightcolor="#00A1D6")
        self.url_entry.pack(side="left", padx=10)

        # 播放量
        row2 = tk.Frame(input_frame, bg="#ffffff")
        row2.pack(fill="x", pady=5, padx=10)
        tk.Label(row2, text="播放数：", bg="#ffffff", font=("Microsoft YaHei", 11)).pack(side="left")
        self.count_entry = tk.Entry(row2, width=15, font=("Microsoft YaHei", 10),
                                    relief="flat", bg="#f8f9fa",
                                    highlightthickness=1, highlightcolor="#00A1D6")
        self.count_entry.pack(side="left", padx=10)

        # ================== 视频信息展示 ==================
        info_frame = tk.Frame(master, bg="#ffffff", relief="groove", bd=1)
        info_frame.pack(pady=12, padx=20, fill="x")

        tk.Label(info_frame, text="视频信息", bg="#ffffff",
                 font=("Microsoft YaHei", 12, "bold"), fg="#333").pack(anchor="w", padx=10, pady=(5, 10))

        # 封面 + 信息 并排布局
        content_frame = tk.Frame(info_frame, bg="#ffffff")
        content_frame.pack(fill="x", padx=10, pady=5)

        # 封面
        self.cover_label = tk.Label(content_frame, bg="#ffffff")
        self.cover_label.pack(side="left", padx=10)

        # 文本信息
        text_frame = tk.Frame(content_frame, bg="#ffffff")
        text_frame.pack(side="left", fill="y", padx=10)

        self.video_title = tk.StringVar(value="视频标题：")
        self.video_author = tk.StringVar(value="作者：")
        self.video_views = tk.StringVar(value="当前播放量：")
        self.target_views = tk.StringVar(value="目标播放量：")

        tk.Label(text_frame, textvariable=self.video_title, bg="#ffffff", font=("Microsoft YaHei", 11)).pack(anchor="w",
                                                                                                             pady=3)
        tk.Label(text_frame, textvariable=self.video_author, bg="#ffffff", font=("Microsoft YaHei", 11)).pack(
            anchor="w", pady=3)
        tk.Label(text_frame, textvariable=self.video_views, bg="#ffffff", font=("Microsoft YaHei", 11)).pack(anchor="w",
                                                                                                             pady=3)
        tk.Label(text_frame, textvariable=self.target_views, bg="#ffffff", font=("Microsoft YaHei", 11)).pack(
            anchor="w", pady=3)

        # ================== 底部操作区 ==================
        action_frame = tk.Frame(master, bg="#ffffff", relief="groove", bd=1)
        action_frame.pack(pady=12, padx=20, fill="x")

        # 进度条
        self.progress_bar = ttk.Progressbar(action_frame, length=460, mode="determinate")
        self.progress_bar.pack(pady=(15, 5), padx=15)

        # 进度提示
        self.progress_label = tk.StringVar(value="等待操作...")
        tk.Label(action_frame, textvariable=self.progress_label, bg="#ffffff",
                 font=("Microsoft YaHei", 11)).pack(pady=(0, 10))

        # 按钮区域（三个按钮：获取信息 / 模拟播放 / 暂停继续）
        button_frame = tk.Frame(action_frame, bg="#ffffff")
        button_frame.pack(pady=(5, 15))

        self.info_button = tk.Button(button_frame, text="📥 获取视频信息",
                                     font=("Microsoft YaHei", 11, "bold"),
                                     bg="#4CAF50", fg="white", relief="flat",
                                     padx=15, pady=8,
                                     activebackground="#388E3C", activeforeground="white",
                                     command=self.fetch_video_info)
        self.info_button.pack(side="left", padx=10)

        self.start_button = tk.Button(button_frame, text="🚀 开始模拟播放",
                                      font=("Microsoft YaHei", 11, "bold"),
                                      bg="#00A1D6", fg="white", relief="flat",
                                      padx=15, pady=8,
                                      activebackground="#0084b4", activeforeground="white",
                                      command=self.start_fake_play,
                                      state="disabled")
        self.start_button.pack(side="left", padx=10)

        self.pause_button = tk.Button(button_frame, text="⏸ 暂停",
                                      font=("Microsoft YaHei", 11, "bold"),
                                      bg="#FF9800", fg="white", relief="flat",
                                      padx=15, pady=8,
                                      activebackground="#F57C00", activeforeground="white",
                                      command=self.toggle_pause,
                                      state="disabled")
        self.pause_button.pack(side="left", padx=10)

        # 缓存视频信息
        self.current_video_info = None

        # 播放控制
        self.is_paused = False
        self.stop_flag = False

    # 获取视频信息
    def fetch_video_info(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入视频网址")
            return

        try:
            title, name, view, face = video.main(url)
            self.current_video_info = {"title": title, "views": int(view), 'name': name, 'face': face}

            # 更新文字信息
            self.video_title.set("视频标题：" + title)
            self.video_author.set("作者：" + name)
            self.video_views.set(f"当前播放量：{view}")
            self.target_views.set("目标播放量：等待设置")

            # 显示封面
            try:
                response = requests.get(face)
                image = Image.open(io.BytesIO(response.content))
                image = image.resize((200, 120))
                photo = ImageTk.PhotoImage(image)
                self.cover_label.config(image=photo)
                self.cover_label.image = photo
            except Exception as e:
                print("封面加载失败:", e)

            # 启用模拟按钮
            self.start_button.config(state="normal")
            self.progress_label.set("视频信息获取成功 ✅")

        except Exception as e:
            messagebox.showerror("错误", f"获取视频信息失败: {e}")

    # 点击开始模拟播放
    def start_fake_play(self):
        if not self.current_video_info:
            messagebox.showerror("错误", "请先获取视频信息")
            return

        count = self.count_entry.get()
        if not count.isdigit():
            messagebox.showerror("错误", "请输入正确的播放量数字")
            return

        video_info = self.current_video_info
        start_views = video_info['views']
        target = start_views + int(count)
        self.target_views.set(f"目标播放量：{target}")

        self.stop_flag = False
        self.is_paused = False
        self.pause_button.config(state="normal", text="⏸ 暂停")

        threading.Thread(target=self.simulate_progress,
                         args=(start_views, target),
                         daemon=True).start()

    # 暂停/继续
    def toggle_pause(self):
        if self.is_paused:
            self.is_paused = False
            self.pause_button.config(text="⏸ 暂停")
            self.progress_label.set("继续播放中...")
        else:
            self.is_paused = True
            self.pause_button.config(text="▶ 继续")
            self.progress_label.set("已暂停...")

    def simulate_progress(self, start_views, target_views_num, mode="processpool", max_workers=5):
        play_count = target_views_num - start_views
        self.progress_bar["value"] = 0
        self.progress_label.set("正在播放中...")

        url = self.url_entry.get()
        step = (target_views_num - start_views) // 100 if target_views_num > start_views else 1

        futures = []

        # 初始化线程池或进程池
        thread_pool = ThreadPoolExecutor(max_workers=max_workers) if mode == "threadpool" else None
        process_pool = ProcessPoolExecutor(max_workers=max_workers) if mode == "processpool" else None

        for i in range(1, 101):
            if self.stop_flag:
                break

            while self.is_paused:
                time.sleep(0.1)

            time.sleep(0.05)
            self.progress_bar["value"] = i

            if play_count > 0 and i % (100 // play_count if play_count < 100 else 1) == 0:
                if mode == "single":
                    run_bili(url)
                elif mode == "threadpool":
                    futures.append(thread_pool.submit(run_bili, url))
                elif mode == "processpool":
                    futures.append(process_pool.submit(run_bili, url))
                else:
                    raise ValueError(f"未知模式: {mode}")

                play_count -= 1

                # 播放后更新真实播放量
                video_info = video.main(url)[-2]
                self.video_views.set(f"当前播放量：{video_info}")
            else:
                current = start_views + i * step
                self.video_views.set(f"当前播放量：{current}")

        # 等待所有线程/进程完成
        for future in futures:
            try:
                future.result()  # 阻塞直到任务完成
            except Exception as e:
                print(f"任务异常: {e}")

        # 关闭线程池/进程池
        if thread_pool:
            thread_pool.shutdown(wait=True)
        if process_pool:
            process_pool.shutdown(wait=True)

        # 最后强制更新一次真实播放量
        video_info = video.main(url)[-2]
        self.video_views.set(f"当前播放量：{video_info}")
        self.progress_label.set("完成 ✅")
        self.pause_button.config(state="disabled")
        messagebox.showinfo("完成", f"刷播放完成！最终播放量：{video_info}")


if __name__ == "__main__":
    root = tk.Tk()
    app = BiliFakePlayApp(root)
    root.mainloop()
