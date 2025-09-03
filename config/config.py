"""
B站视频刷播放量工具 - 主配置文件
提取项目中的硬编码配置，便于维护和修改
"""

import os
import logging
from typing import List, Dict, Any

# ==================== 设备型号配置 ====================
DEVICE_MODELS = [
    "Pixel 7", "Redmi K50", "ONEPLUS 9 Pro", "Vivo V23", "MI 12X",
    "SM-G998B", "Xiaomi 11T", "OPPO Reno8", "Pixel 7 Pro", "Lenovo Legion Y90",
    "Realme GT Neo3", "MI 11 Ultra", "Redmi Note 11", "ONEPLUS A6013", "VOG-L29",
    "P50 Pro", "OPPO Find X5", "Vivo X80", "Pixel 6a", "Redmi K40",
    "SM-G991U", "Xiaomi 12S", "Realme GT", "ONEPLUS 8T", "Vivo Y76",
    "OPPO Reno7", "MI 10 Pro", "Pixel 5", "Lenovo K12 Pro", "Redmi Note 10",
    "SM-G990F", "Xiaomi 11 Lite", "OPPO Find X3", "Vivo V21", "ONEPLUS 7T",
    "MI 9T", "Pixel 4 XL", "Realme X50 Pro", "Redmi K30", "SM-G988B",
    "Xiaomi Mi Mix 4", "OPPO Reno6", "Vivo X60", "Lenovo Legion 2 Pro", "ONEPLUS Nord 2",
    "Pixel 3a", "MI 8 Lite", "Redmi Note 9", "Realme 7 Pro", "SM-G985F",
    "Xiaomi Poco F3", "Pixel 6 Pro", "Redmi K20", "ONEPLUS 6T", "Vivo V19",
    "MI 11", "SM-G960F", "Xiaomi Mi 10", "OPPO Reno4", "Vivo X50",
    "Realme 6", "Lenovo Z6", "Pixel 5a", "Redmi Note 8", "ONEPLUS 5T",
    "MI 10T", "SM-G973F", "Xiaomi Mi 9", "OPPO Reno3", "Vivo Y20",
    "Realme X3", "Lenovo K10", "Pixel 4a", "Redmi Note 7", "ONEPLUS 6",
    "MI 9 SE", "SM-G970F", "Xiaomi Mi 8", "OPPO Reno2", "Vivo V17",
    "Realme 5 Pro", "Lenovo Z5", "Pixel 3 XL", "Redmi K30 Pro", "ONEPLUS 7",
    "MI 8 Pro", "SM-G965F", "Xiaomi Mi 8 Lite", "OPPO Reno", "Vivo Y17",
    "Realme 3 Pro", "Lenovo K8 Plus", "Pixel 2 XL", "Redmi Note 6 Pro", "ONEPLUS 5",
    "MI 6X", "SM-G955F", "Xiaomi Mi 6", "OPPO F11 Pro", "Vivo V15",
    "Realme 2 Pro", "Lenovo Z2 Plus", "Pixel 2", "Redmi Note 5", "ONEPLUS 3T"
]

# ==================== 代理配置 ====================
PROXY_CONFIG = {
    'enabled': True,
    'api_url': 'http://api2.xkdaili.com/tools/XApi.ashx?apikey=XK69862370B1CA650629&qty=100&format=txt&split=0&sign=87a269171ead05ba5185eba8eb5a162a&time=3',
    'timeout': 10,
    'retry_times': 3,
    'rotation_interval': 60,  # 代理轮换间隔（秒）
    'max_failures': 3,  # 最大失败次数
}

# ==================== 日志配置 ====================
LOG_CONFIG = {
    'format': '%(asctime)s %(levelname)s [%(filename)s %(funcName)s line:%(lineno)d]: %(message)s',
    'level': int(os.getenv('LOG_LEVEL', logging.INFO)),  # 默认INFO级别
    'datefmt': None,
    'file': 'bilibili.log',
    'max_size': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
}

# ==================== 网络请求配置 ====================
REQUEST_CONFIG = {
    'timeout': 30,
    'retry_times': 3,
    'delay_range': (1, 3),  # 请求间隔范围（秒）
    'user_agent': 'Mozilla/5.0 (Linux; Android 12; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
}


# ==================== 配置获取函数 ====================
def get_config() -> Dict[str, Any]:
    """获取所有配置"""
    return {
        'device_models': DEVICE_MODELS,
        'proxy_config': PROXY_CONFIG,
        'log_config': LOG_CONFIG,
        'request_config': REQUEST_CONFIG,
    }


def get_device_models() -> List[str]:
    """获取设备型号列表"""
    return DEVICE_MODELS


def get_proxy_config() -> Dict[str, Any]:
    """获取代理配置"""
    return PROXY_CONFIG


def get_log_config() -> Dict[str, Any]:
    """获取日志配置"""
    return LOG_CONFIG


def get_request_config() -> Dict[str, Any]:
    """获取请求配置"""
    return REQUEST_CONFIG


# ==================== 配置验证 ====================
def validate_config() -> bool:
    """验证配置的有效性"""
    try:
        # 检查必要的配置项
        if not DEVICE_MODELS:
            print("错误: 设备型号列表不能为空")
            return False

        return True
    except Exception as e:
        print(f"配置验证失败: {e}")
        return False
