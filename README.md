# B站视频刷播放量工具

一个基于Python的B站视频播放量模拟工具，通过模拟移动端API请求来增加视频播放量。

## ⚠️ 免责声明

**本项目仅供学习和研究使用，请勿用于商业用途或恶意刷量。使用本工具产生的任何后果由使用者自行承担。**

## 🚀 功能特性

- **视频信息获取**：自动解析B站视频链接，获取视频标题、作者、当前播放量等信息
- **智能参数生成**：自动生成B站移动端API所需的各种加密参数
    - buvid（设备标识）
    - device_id（设备ID）
    - fp_local（指纹参数）
    - session_id（会话ID）
    - sign（签名参数）
- **代理IP支持**：支持代理IP轮换，避免IP被封
- **多线程处理**：支持并发请求，提高效率
- **图形化界面**：基于Tkinter的现代化GUI界面
- **实时进度显示**：显示操作进度和状态信息
- **彩色日志系统**：支持控制台彩色输出和文件日志记录
- **配置化管理**：支持环境变量和配置文件管理

## 📋 系统要求

- Python 3.7+
- Windows 10/11 (推荐)
- 网络连接
- 代理IP服务（可选）

## 🛠️ 安装说明

### 1. 克隆项目

```bash
git clone <repository-url>
cd bilibili_video
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置环境

```bash
# 复制配置文件
cp config/config.example.py config/config.py

# 编辑配置文件，设置你的参数
# 或者设置环境变量
export LOG_LEVEL=20
export LOG_PRESET=development
export PROXY_ENABLED=true
```

### 4. 运行程序

```bash
python main.py
```

## 📦 依赖包

主要依赖包包括：

- `requests` - HTTP请求库
- `PIL/Pillow` - 图像处理
- `pycryptodome` - 加密算法库
- `frida` - 动态插桩工具（hook脚本使用）
- `tkinter` - GUI界面（Python内置）

## 🎯 使用方法

### 基本操作流程

1. **启动程序**
    - 运行 `python main.py`
    - 程序会打开图形化界面

2. **输入视频信息**
    - 在"视频网址"框中输入B站视频链接
    - 在"播放量"框中输入目标播放量

3. **获取视频信息**
    - 点击"📥 获取视频信息"按钮
    - 程序会自动解析视频并显示相关信息

4. **开始模拟播放**
    - 点击"▶️ 开始模拟播放"按钮
    - 程序会开始模拟播放请求

5. **监控进度**
    - 通过进度条和状态提示监控操作进度
    - 可以随时暂停/继续操作

### 高级功能

- **代理设置**：在 `config/config.py` 中配置代理IP服务
- **参数调优**：在 `config/config.py` 中调整各种参数生成逻辑
- **Hook脚本**：使用 `hook/` 目录下的Frida脚本进行动态分析
- **日志管理**：支持多种日志级别和输出方式

## 🏗️ 项目结构

```
bilibili_video/
├── main.py              # 主程序入口，GUI界面
├── bilibli.py           # 核心爬虫逻辑
├── video.py             # 视频信息处理
├── config/              # 配置文件目录
│   ├── config.py        # 主配置文件
│   └── config.example.py # 配置示例文件
├── core/                # 核心功能模块
│   ├── parms.py         # 参数生成模块
│   ├── proxy.py         # 代理服务模块
│   └── __init__.py
├── utils/               # 工具函数
│   ├── logger.py        # 彩色日志配置类
│   ├── util.py          # 通用工具函数
│   └── __init__.py
├── hook/                # Frida Hook脚本
│   ├── hook-*.py        # 各种Hook脚本
│   └── hook-onload.js   # JavaScript Hook脚本
├── logs/                # 日志文件目录
├── cache/               # 缓存文件目录
├── backups/             # 备份文件目录
└── requirements.txt      # 依赖包列表
```

## 🔧 配置说明

### 日志配置

支持三种预设配置：

```python
from utils.logger import get_logger

# 开发环境 - 彩色输出，控制台+文件
logger = get_logger(preset="development")

# 生产环境 - 无彩色，仅文件输出
logger = get_logger(preset="production")

# 测试环境 - 彩色输出，仅控制台
logger = get_logger(preset="testing")
```

### 环境变量配置

```bash
# 日志配置
export LOG_LEVEL=20          # 日志级别 (10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL)
export LOG_PRESET=development # 日志预设 (development, production, testing)

# 代理配置
export PROXY_ENABLED=true    # 是否启用代理

# B站API配置
export BILIBILI_APP_KEY=your_app_key
export BILIBILI_APP_SECRET=your_app_secret

# 请求配置
export REQUEST_TIMEOUT=30    # 请求超时时间
```

### 代理配置

在 `config/config.py` 中配置代理IP服务：

```python
PROXY_CONFIG = {
    'enabled': True,
    'api_url': 'http://your-proxy-api-url',
    'timeout': 10,
    'retry_times': 3,
    'rotation_interval': 60,
    'max_failures': 3,
}
```

### 设备参数配置

在 `config/config.py` 中调整设备型号列表和其他参数：

```python
DEVICE_MODELS = [
    "Pixel 7", "Redmi K50", "ONEPLUS 9 Pro",
    # 添加更多设备型号
]
```

## 📊 日志系统

### 日志级别

- **DEBUG (10)**: 详细的调试信息
- **INFO (20)**: 一般信息
- **WARNING (30)**: 警告信息
- **ERROR (40)**: 错误信息
- **CRITICAL (50)**: 严重错误

### 日志输出

- **控制台输出**: 支持彩色显示，便于开发调试
- **文件输出**: 自动轮转，避免单个文件过大
- **日志轮转**: 默认10MB一个文件，保留5个备份

### 使用示例

```python
from utils.logger import get_logger

# 获取日志器
logger = get_logger()

# 记录不同级别的日志
logger.debug("调试信息")
logger.info("普通信息")
logger.warning("警告信息")
logger.error("错误信息")
logger.critical("严重错误")

# 异常处理
try:
    # 你的代码
    pass
except Exception as e:
    logger.error(f"操作失败: {e}")
    logger.exception("详细错误堆栈")
```

## ⚡ 性能优化

- 使用多线程处理并发请求
- 智能参数缓存，避免重复计算
- 代理IP轮换，提高成功率
- 请求间隔随机化，模拟真实用户行为
- 日志异步写入，提高性能

## 🚨 注意事项

1. **合规使用**：请遵守B站用户协议，不要恶意刷量
2. **频率控制**：建议控制请求频率，避免被检测
3. **代理质量**：使用高质量的代理IP，提高成功率
4. **参数更新**：B站可能会更新API参数，需要及时调整代码
5. **日志管理**：定期清理日志文件，避免占用过多磁盘空间

## 🐛 常见问题

### Q: 程序无法启动

A: 检查Python版本和依赖包是否正确安装

### Q: 获取视频信息失败

A: 检查网络连接和视频链接是否有效

### Q: 模拟播放失败

A: 检查代理IP是否可用，参数是否正确

### Q: 被B站检测

A: 降低请求频率，更换代理IP，更新参数生成逻辑

### Q: 日志文件过大

A: 调整日志轮转配置，或定期清理日志文件

### Q: 控制台没有彩色输出

A: 检查终端是否支持ANSI颜色，或设置 `use_color=False`

## 📝 更新日志

### v1.1.0

- 新增彩色日志系统
- 支持多种日志预设配置
- 配置文件重构，支持环境变量
- 日志文件自动轮转

### v1.0.0

- 初始版本发布
- 支持基本的视频信息获取和播放量模拟
- 图形化界面
- 多线程支持

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进项目！

### 贡献方式

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目仅供学习和研究使用，请勿用于商业用途。

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交GitHub Issue
- 发送邮件至：[2480419172@qq.com]

## 🙏 致谢

感谢所有为这个项目做出贡献的开发者！

---

**再次提醒：本项目仅供学习研究使用，请遵守相关法律法规和平台规则。**
