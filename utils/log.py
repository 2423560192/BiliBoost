"""
彩色日志配置类
支持控制台彩色输出和文件日志记录
"""

import os
import sys
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler


# ANSI颜色代码
class Colors:
    """ANSI颜色代码"""
    # 前景色
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # 背景色
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # 样式
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'

    # 重置
    RESET = '\033[0m'


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""

    # 日志级别对应的颜色
    COLORS = {
        'DEBUG': Colors.CYAN,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.BG_RED + Colors.WHITE + Colors.BOLD,
    }

    def __init__(self, fmt: str = None, datefmt: str = None, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record):
        # 保存原始格式
        original_fmt = self._style._fmt

        if self.use_color and record.levelname in self.COLORS:
            # 添加颜色
            color = self.COLORS[record.levelname]
            self._style._fmt = f"{color}{original_fmt}{Colors.RESET}"

        # 格式化日志
        result = super().format(record)

        # 恢复原始格式
        self._style._fmt = original_fmt

        return result


class LoggerConfig:
    """日志配置类"""

    def __init__(self,
                 name: str = "BilibiliVideo",
                 level: int = logging.INFO,
                 log_dir: str = "logs",
                 max_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5,
                 use_color: bool = True,
                 console_output: bool = True,
                 file_output: bool = True):
        """
        初始化日志配置

        Args:
            name: 日志器名称
            level: 日志级别
            log_dir: 日志文件目录
            max_size: 单个日志文件最大大小
            backup_count: 保留的日志文件数量
            use_color: 是否使用彩色输出
            console_output: 是否输出到控制台
            file_output: 是否输出到文件
        """
        self.name = name
        self.level = level
        self.log_dir = log_dir
        self.max_size = max_size
        self.backup_count = backup_count
        self.use_color = use_color
        self.console_output = console_output
        self.file_output = file_output

        # 创建日志器
        self.logger = self._create_logger()

    def _create_logger(self) -> logging.Logger:
        """创建日志器"""
        logger = logging.getLogger(self.name)
        logger.setLevel(self.level)

        # 清除已有的处理器
        logger.handlers.clear()

        # 控制台处理器
        if self.console_output:
            console_handler = self._create_console_handler()
            logger.addHandler(console_handler)

        # 文件处理器
        if self.file_output:
            file_handler = self._create_file_handler()
            logger.addHandler(file_handler)

        return logger

    def _create_console_handler(self) -> logging.StreamHandler:
        """创建控制台处理器"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.level)

        # 控制台格式（带颜色）
        console_fmt = (
            f"{Colors.BOLD}%(asctime)s{Colors.RESET} "  # 时间加粗
            f"{Colors.CYAN}%(levelname)s{Colors.RESET} "  # 级别青色
            f"{Colors.YELLOW}[%(filename)s %(funcName)s line:%(lineno)d]{Colors.RESET}: "  # 文件名/函数名/行号黄色
            f"{Colors.GREEN}%(message)s{Colors.RESET}"  # 消息绿色
        )

        formatter = ColoredFormatter(console_fmt, use_color=self.use_color)
        console_handler.setFormatter(formatter)

        return console_handler

    def _create_file_handler(self) -> RotatingFileHandler:
        """创建文件处理器"""
        # 确保日志目录存在
        os.makedirs(self.log_dir, exist_ok=True)

        # 日志文件路径
        log_file = os.path.join(self.log_dir, f"{self.name.lower()}.log")

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=self.max_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(self.level)

        # 文件格式（不包含颜色代码）
        file_fmt = "%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
        formatter = logging.Formatter(file_fmt)
        file_handler.setFormatter(formatter)

        return file_handler

    def set_level(self, level: int):
        """设置日志级别"""
        self.level = level
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)

    def add_context(self, context: Dict[str, Any]):
        """添加上下文信息到日志记录"""
        for key, value in context.items():
            setattr(self.logger, key, value)

    def get_logger(self) -> logging.Logger:
        """获取日志器实例"""
        return self.logger

    def log_startup(self):
        """记录启动信息"""
        self.logger.info("=" * 60)
        self.logger.info(f"🚀 {self.name} 服务启动")
        self.logger.info(f"📅 启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"�� 日志级别: {logging.getLevelName(self.level)}")
        self.logger.info(f"📁 日志目录: {os.path.abspath(self.log_dir)}")
        self.logger.info(f"🎨 彩色输出: {'启用' if self.use_color else '禁用'}")
        self.logger.info("=" * 60)

    def log_shutdown(self):
        """记录关闭信息"""
        self.logger.info("=" * 60)
        self.logger.info(f"🛑 {self.name} 服务关闭")
        self.logger.info(f"📅 关闭时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info("=" * 60)


# 预定义的日志配置
class LoggerPresets:
    """日志配置预设"""

    @staticmethod
    def development() -> LoggerConfig:
        """开发环境配置"""
        return LoggerConfig(
            name="BilibiliVideo-Dev",
            level=logging.DEBUG,
            use_color=True,
            console_output=True,
            file_output=True
        )

    @staticmethod
    def production() -> LoggerConfig:
        """生产环境配置"""
        return LoggerConfig(
            name="BilibiliVideo-Prod",
            level=logging.INFO,
            use_color=False,
            console_output=False,
            file_output=True
        )

    @staticmethod
    def testing() -> LoggerConfig:
        """测试环境配置"""
        return LoggerConfig(
            name="BilibiliVideo-Test",
            level=logging.WARNING,
            use_color=True,
            console_output=True,
            file_output=False
        )


# 全局日志器实例
_default_logger = None


def get_logger(name: str = "BilibiliVideo", preset: str = "development") -> logging.Logger:
    """
    获取日志器实例

    Args:
        name: 日志器名称
        preset: 预设配置类型 ('development', 'production', 'testing')

    Returns:
        logging.Logger: 日志器实例
    """
    global _default_logger

    if _default_logger is None:
        if preset == "development":
            _default_logger = LoggerPresets.development()
        elif preset == "production":
            _default_logger = LoggerPresets.production()
        elif preset == "testing":
            _default_logger = LoggerPresets.testing()
        else:
            _default_logger = LoggerConfig(name=name)

    return _default_logger.get_logger()


logger = get_logger()
